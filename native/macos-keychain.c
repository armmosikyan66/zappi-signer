#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* macOS keychain helper. Secrets travel on stdin and stdout, never in argv.
   Items use kSecAttrAccessibleWhenUnlockedThisDeviceOnly and are not synchronizable.
   Exit 0 success, exit 2 missing, exit 1 failure. Stderr never contains the secret. */

static const char *service = "zappi-signer";

static void fail(const char *message) {
  fprintf(stderr, "%s\n", message);
  exit(1);
}

static int account_ok(const char *account) {
  size_t n = strlen(account);
  if (n < 1 || n > 64) return 0;
  for (size_t i = 0; i < n; i++) {
    char c = account[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return 0;
  }
  return 1;
}

static CFDataRef read_stdin(void) {
  unsigned char buf[8193];
  size_t n = fread(buf, 1, sizeof buf, stdin);
  if (n == 0 || n > 8192) fail("keychain unavailable");
  CFDataRef data = CFDataCreate(NULL, buf, (CFIndex)n);
  memset(buf, 0, n);
  if (!data) fail("keychain unavailable");
  return data;
}

static CFMutableDictionaryRef lookup_query(CFStringRef account) {
  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
  );
  if (!query) fail("keychain unavailable");
  CFStringRef serviceName = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
  if (!serviceName) {
    CFRelease(query);
    fail("keychain unavailable");
  }
  CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(query, kSecAttrService, serviceName);
  CFRelease(serviceName);
  CFDictionarySetValue(query, kSecAttrAccount, account);
  CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse);

  const char *home = getenv("HOME");
  if (home && strlen(home) < 4000) {
    char path[4096];
    snprintf(path, sizeof path, "%s/Library/Keychains/login.keychain-db", home);
    SecKeychainRef keychain = NULL;
    if (SecKeychainOpen(path, &keychain) == errSecSuccess && keychain) {
      CFDictionarySetValue(query, kSecUseKeychain, keychain);
      CFRelease(keychain);
    }
  }
  return query;
}

static CFDataRef copy_secret(CFStringRef account) {
  CFMutableDictionaryRef query = lookup_query(account);
  CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
  CFTypeRef item = NULL;
  OSStatus status = SecItemCopyMatching(query, &item);
  CFRelease(query);
  if (status == errSecSuccess && item && CFGetTypeID(item) == CFDataGetTypeID()) {
    CFDataRef data = (CFDataRef)item;
    if (CFDataGetLength(data) > 0) return data;
  }
  if (item) CFRelease(item);
  return NULL;
}

static int store_secret(CFStringRef account, CFDataRef data) {
  CFMutableDictionaryRef lookup = lookup_query(account);
  SecItemDelete(lookup);
  CFMutableDictionaryRef add = CFDictionaryCreateMutableCopy(NULL, 0, lookup);
  CFRelease(lookup);
  if (!add) return 0;
  CFDictionarySetValue(add, kSecValueData, data);
  CFDictionarySetValue(add, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
  CFDictionarySetValue(add, kSecAttrSynchronizable, kCFBooleanFalse);
  CFDictionarySetValue(add, kSecAttrLabel, CFSTR("zappi-signer"));
  OSStatus status = SecItemAdd(add, NULL);
  CFRelease(add);
  return status == errSecSuccess;
}

/* The device factor is 32 stable bytes that stay on this device.
   Prefer a Secure Enclave key: the factor is ECIES-sealed to that key, because
   an ECDSA signature is not stable. An unsigned helper is often refused the
   enclave (errSecMissingEntitlement). Then the factor is a this-device-only
   keychain item that is not synced. Either way a copied vault cannot open it. */

static CFDataRef factor_tag(const char *account) {
  char tag[80];
  if (snprintf(tag, sizeof tag, "zappi-device.%s", account) >= (int)sizeof tag) return NULL;
  return CFDataCreate(NULL, (const UInt8 *)tag, (CFIndex)strlen(tag));
}

static CFMutableDictionaryRef factor_query(const char *account) {
  CFStringRef accountName = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
  if (!accountName) return NULL;
  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
  );
  if (!query) {
    CFRelease(accountName);
    return NULL;
  }
  CFStringRef serviceName = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
  if (!serviceName) {
    CFRelease(query);
    CFRelease(accountName);
    return NULL;
  }
  CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionarySetValue(query, kSecAttrService, serviceName);
  CFDictionarySetValue(query, kSecAttrAccount, accountName);
  CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse);
  CFRelease(serviceName);
  CFRelease(accountName);
  return query;
}

static SecKeyRef load_or_create_key(const char *account) {
  CFDataRef tag = factor_tag(account);
  if (!tag) return NULL;
  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
  );
  if (!query) {
    CFRelease(tag);
    return NULL;
  }
  CFDictionarySetValue(query, kSecClass, kSecClassKey);
  CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
  CFDictionarySetValue(query, kSecAttrApplicationTag, tag);
  CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
  CFDictionarySetValue(query, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
  CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
  CFTypeRef found = NULL;
  if (SecItemCopyMatching(query, &found) == errSecSuccess && found) {
    CFRelease(query);
    CFRelease(tag);
    return (SecKeyRef)found;
  }

  CFErrorRef error = NULL;
  SecAccessControlRef access = SecAccessControlCreateWithFlags(
    NULL,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAccessControlPrivateKeyUsage,
    &error
  );
  if (error) CFRelease(error);
  if (!access) {
    CFRelease(query);
    CFRelease(tag);
    return NULL;
  }
  int bits = 256;
  CFNumberRef size = CFNumberCreate(NULL, kCFNumberIntType, &bits);
  CFMutableDictionaryRef privateAttrs = CFDictionaryCreateMutable(
    NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
  );
  CFMutableDictionaryRef create = CFDictionaryCreateMutable(
    NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
  );
  if (!size || !privateAttrs || !create) {
    if (size) CFRelease(size);
    if (privateAttrs) CFRelease(privateAttrs);
    if (create) CFRelease(create);
    CFRelease(access);
    CFRelease(query);
    CFRelease(tag);
    return NULL;
  }
  CFDictionarySetValue(privateAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
  CFDictionarySetValue(privateAttrs, kSecAttrApplicationTag, tag);
  CFDictionarySetValue(privateAttrs, kSecAttrAccessControl, access);
  CFDictionarySetValue(create, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
  CFDictionarySetValue(create, kSecAttrKeySizeInBits, size);
  CFDictionarySetValue(create, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
  CFDictionarySetValue(create, kSecUseDataProtectionKeychain, kCFBooleanTrue);
  CFDictionarySetValue(create, kSecPrivateKeyAttrs, privateAttrs);
  error = NULL;
  SecKeyRef created = SecKeyCreateRandomKey(create, &error);
  if (error) CFRelease(error);
  CFRelease(size);
  CFRelease(privateAttrs);
  CFRelease(create);
  CFRelease(access);
  CFRelease(query);
  CFRelease(tag);
  if (created) return created;
  found = NULL;
  CFDataRef tagAgain = factor_tag(account);
  if (!tagAgain) return NULL;
  CFMutableDictionaryRef retry = CFDictionaryCreateMutable(
    NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
  );
  if (!retry) {
    CFRelease(tagAgain);
    return NULL;
  }
  CFDictionarySetValue(retry, kSecClass, kSecClassKey);
  CFDictionarySetValue(retry, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
  CFDictionarySetValue(retry, kSecAttrApplicationTag, tagAgain);
  CFDictionarySetValue(retry, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
  CFDictionarySetValue(retry, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
  CFDictionarySetValue(retry, kSecUseDataProtectionKeychain, kCFBooleanTrue);
  CFDictionarySetValue(retry, kSecReturnRef, kCFBooleanTrue);
  CFDictionarySetValue(retry, kSecMatchLimit, kSecMatchLimitOne);
  if (SecItemCopyMatching(retry, &found) == errSecSuccess && found) {
    CFRelease(retry);
    CFRelease(tagAgain);
    return (SecKeyRef)found;
  }
  CFRelease(retry);
  CFRelease(tagAgain);
  return NULL;
}

static CFDataRef load_wrap(const char *account) {
  CFMutableDictionaryRef query = factor_query(account);
  if (!query) return NULL;
  CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
  CFTypeRef item = NULL;
  OSStatus status = SecItemCopyMatching(query, &item);
  CFRelease(query);
  if (status == errSecSuccess && item && CFGetTypeID(item) == CFDataGetTypeID() && CFDataGetLength(item) > 0) {
    return (CFDataRef)item;
  }
  if (item) CFRelease(item);
  return NULL;
}

static int store_wrap(const char *account, CFDataRef cipher) {
  CFMutableDictionaryRef query = factor_query(account);
  if (!query) return 0;
  CFDictionarySetValue(query, kSecValueData, cipher);
  CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
  CFDictionarySetValue(query, kSecAttrLabel, CFSTR("zappi-signer"));
  OSStatus status = SecItemAdd(query, NULL);
  CFRelease(query);
  if (status == errSecSuccess) return 1;
  if (status == errSecDuplicateItem) return 2;
  return 0;
}

static int unwrap_factor(SecKeyRef priv, CFDataRef cipher, unsigned char out[32]) {
  CFErrorRef error = NULL;
  CFDataRef plain = SecKeyCreateDecryptedData(
    priv,
    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
    cipher,
    &error
  );
  if (error) CFRelease(error);
  if (!plain || CFDataGetLength(plain) != 32) {
    if (plain) CFRelease(plain);
    return 0;
  }
  memcpy(out, CFDataGetBytePtr(plain), 32);
  CFRelease(plain);
  return 1;
}

static CFDataRef wrap_factor(SecKeyRef priv, const unsigned char plain[32]) {
  SecKeyRef pub = SecKeyCopyPublicKey(priv);
  if (!pub) return NULL;
  CFDataRef data = CFDataCreate(NULL, plain, 32);
  if (!data) {
    CFRelease(pub);
    return NULL;
  }
  CFErrorRef error = NULL;
  CFDataRef cipher = SecKeyCreateEncryptedData(
    pub,
    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
    data,
    &error
  );
  if (error) CFRelease(error);
  CFRelease(data);
  CFRelease(pub);
  return cipher;
}

static void write_b64(const unsigned char *data, size_t len) {
  static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char out[64];
  size_t n = 0;
  for (size_t i = 0; i < len; i += 3) {
    unsigned int chunk = (unsigned int)data[i] << 16;
    if (i + 1 < len) chunk |= (unsigned int)data[i + 1] << 8;
    if (i + 2 < len) chunk |= (unsigned int)data[i + 2];
    out[n++] = table[(chunk >> 18) & 63];
    out[n++] = table[(chunk >> 12) & 63];
    out[n++] = i + 1 < len ? table[(chunk >> 6) & 63] : '=';
    out[n++] = i + 2 < len ? table[chunk & 63] : '=';
  }
  fwrite(out, 1, n, stdout);
  fflush(stdout);
}

static int software_factor(const char *account_c) {
  CFStringRef account = CFStringCreateWithCString(NULL, account_c, kCFStringEncodingUTF8);
  if (!account) return 1;
  unsigned char plain[32];
  CFDataRef existing = copy_secret(account);
  if (existing) {
    int ok = CFDataGetLength(existing) == 32;
    if (ok) memcpy(plain, CFDataGetBytePtr(existing), 32);
    CFRelease(existing);
    CFRelease(account);
    if (!ok) return 1;
    write_b64(plain, 32);
    memset(plain, 0, sizeof plain);
    return 0;
  }
  if (SecRandomCopyBytes(kSecRandomDefault, sizeof plain, plain) != errSecSuccess) {
    CFRelease(account);
    return 1;
  }
  CFDataRef data = CFDataCreate(NULL, plain, 32);
  if (!data) {
    memset(plain, 0, sizeof plain);
    CFRelease(account);
    return 1;
  }
  int stored = store_secret(account, data);
  CFRelease(data);
  CFRelease(account);
  if (!stored) {
    memset(plain, 0, sizeof plain);
    return 1;
  }
  write_b64(plain, 32);
  memset(plain, 0, sizeof plain);
  return 0;
}

static int print_factor(const char *account) {
  SecKeyRef priv = load_or_create_key(account);
  if (!priv) return software_factor(account);
  unsigned char plain[32];
  CFDataRef wrapped = load_wrap(account);
  if (wrapped) {
    int ok = unwrap_factor(priv, wrapped, plain);
    CFRelease(wrapped);
    CFRelease(priv);
    if (!ok) return 1;
    write_b64(plain, 32);
    memset(plain, 0, sizeof plain);
    return 0;
  }
  if (SecRandomCopyBytes(kSecRandomDefault, sizeof plain, plain) != errSecSuccess) {
    CFRelease(priv);
    return 1;
  }
  CFDataRef cipher = wrap_factor(priv, plain);
  int stored = cipher ? store_wrap(account, cipher) : 0;
  if (cipher) CFRelease(cipher);
  if (stored != 1) {
    wrapped = load_wrap(account);
    if (!wrapped || !unwrap_factor(priv, wrapped, plain)) {
      if (wrapped) CFRelease(wrapped);
      memset(plain, 0, sizeof plain);
      CFRelease(priv);
      return 1;
    }
    CFRelease(wrapped);
  }
  CFRelease(priv);
  write_b64(plain, 32);
  memset(plain, 0, sizeof plain);
  return 0;
}

static int prompt_presence(CFStringRef account) {
  CFErrorRef error = NULL;
  SecAccessControlRef access = SecAccessControlCreateWithFlags(
    NULL,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAccessControlUserPresence,
    &error
  );
  if (error) CFRelease(error);
  if (!access) return 0;

  CFMutableDictionaryRef base = lookup_query(account);
  CFMutableDictionaryRef copy = CFDictionaryCreateMutableCopy(NULL, 0, base);
  if (!copy) {
    CFRelease(base);
    CFRelease(access);
    return 0;
  }
  CFDictionarySetValue(copy, kSecReturnData, kCFBooleanTrue);
  CFDictionarySetValue(copy, kSecMatchLimit, kSecMatchLimitOne);
  CFDictionarySetValue(copy, kSecUseOperationPrompt, CFSTR("Authorize Zappi"));
  CFDictionarySetValue(copy, kSecAttrAccessControl, access);
  CFTypeRef item = NULL;
  if (SecItemCopyMatching(copy, &item) == errSecSuccess) {
    if (item) CFRelease(item);
    CFRelease(copy);
    CFRelease(base);
    CFRelease(access);
    return 1;
  }

  CFDictionarySetValue(base, kSecValueData, CFSTR("zappi-presence"));
  CFDictionarySetValue(base, kSecAttrAccessControl, access);
  CFDictionarySetValue(base, kSecAttrLabel, CFSTR("zappi-signer"));
  int added = SecItemAdd(base, NULL) == errSecSuccess;
  item = NULL;
  int ok = added && SecItemCopyMatching(copy, &item) == errSecSuccess;
  if (item) CFRelease(item);
  CFRelease(copy);
  CFRelease(base);
  CFRelease(access);
  return ok;
}

int main(int argc, char **argv) {
  if (argc < 3) fail("keychain account refused");
  const char *op = argv[1];
  const char *account_c = argv[2];
  if (!account_ok(account_c)) fail("keychain account refused");
  CFStringRef account = CFStringCreateWithCString(NULL, account_c, kCFStringEncodingUTF8);
  if (!account) fail("keychain unavailable");

  if (strcmp(op, "get") == 0) {
    CFDataRef data = copy_secret(account);
    CFRelease(account);
    if (!data) exit(2);
    fwrite(CFDataGetBytePtr(data), 1, (size_t)CFDataGetLength(data), stdout);
    CFRelease(data);
    return 0;
  }
  if (strcmp(op, "set") == 0) {
    CFDataRef data = read_stdin();
    int ok = store_secret(account, data);
    CFRelease(data);
    CFRelease(account);
    if (!ok) fail("keychain unavailable");
    return 0;
  }
  if (strcmp(op, "delete") == 0) {
    CFMutableDictionaryRef query = lookup_query(account);
    SecItemDelete(query);
    CFRelease(query);
    CFRelease(account);
    return 0;
  }
  if (strcmp(op, "presence") == 0) {
    int ok = prompt_presence(account);
    CFRelease(account);
    if (!ok) fail("keychain unavailable");
    return 0;
  }
  if (strcmp(op, "factor") == 0) {
    int failed = print_factor(account_c);
    CFRelease(account);
    if (failed) fail("keychain unavailable");
    return 0;
  }
  CFRelease(account);
  fail("keychain unavailable");
}
