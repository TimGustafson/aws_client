// RFC3986-compliant URI encoding for AWS SigV4
// 
// This implementation fixes the canonical query string encoding to be fully
// compliant with RFC3986, which AWS SigV4 requires.
//
// Per AWS documentation and RFC3986 section 2.3, only these characters 
// should remain unencoded (unreserved characters):
// - Uppercase letters: A-Z
// - Lowercase letters: a-z  
// - Digits: 0-9
// - Hyphen: -
// - Period: .
// - Underscore: _
// - Tilde: ~
//
// All other characters MUST be percent-encoded, including characters that
// Dart's Uri.encodeQueryComponent() leaves unencoded like *, !, ', (, and ).

/// Encodes a string according to RFC3986 for use in AWS SigV4 canonical requests.
/// 
/// This encoding is stricter than standard URL encoding - it only allows
/// unreserved characters (A-Z, a-z, 0-9, -, ., _, ~) to remain unencoded.
String _encodeRFC3986(String value) {
  final StringBuffer result = StringBuffer();
  
  for (int i = 0; i < value.length; i++) {
    final int char = value.codeUnitAt(i);
    
    // Check if character is in the unreserved set per RFC3986
    if ((char >= 0x41 && char <= 0x5A) ||  // A-Z
        (char >= 0x61 && char <= 0x7A) ||  // a-z
        (char >= 0x30 && char <= 0x39) ||  // 0-9
        char == 0x2D ||                     // -
        char == 0x2E ||                     // .
        char == 0x5F ||                     // _
        char == 0x7E) {                     // ~
      result.writeCharCode(char);
    } else {
      // Percent-encode all other characters
      // Handle UTF-8 multi-byte characters
      final bytes = value.substring(i, i + 1).codeUnits;
      for (final byte in bytes) {
        result.write('%${byte.toRadixString(16).toUpperCase().padLeft(2, '0')}');
      }
    }
  }
  
  return result.toString();
}

/// Creates a canonical query string from query parameters.
/// 
/// This is used in AWS SigV4 signature calculation. The query parameters
/// must be:
/// 1. Sorted by parameter name (byte order)
/// 2. Each name and value must be RFC3986 encoded
/// 3. Joined with = between name and value
/// 4. Joined with & between parameters
String canonicalQueryParameters(Map<String, String> queryParams) {
  if (queryParams.isEmpty) return '';
  
  final sortedKeys = queryParams.keys.toList()..sort();
  
  return sortedKeys
      .map((key) => '${_encodeRFC3986(key)}=${_encodeRFC3986(queryParams[key]!)}')
      .join('&');
}

/// Creates a canonical query string from query parameters that may have
/// multiple values per key.
///
/// This handles the case where query parameters can have multiple values.
/// Per AWS SigV4 specification:
/// - Parameters with the same name should be sorted by their values
/// - Each parameter instance is encoded separately  
String canonicalQueryParametersAll(Map<String, List<String>> queryParams) {
  if (queryParams.isEmpty) return '';
  
  // Flatten to list of key-value pairs
  final List<MapEntry<String, String>> pairs = [];
  
  for (final entry in queryParams.entries) {
    for (final value in entry.value) {
      pairs.add(MapEntry(entry.key, value));
    }
  }
  
  // Sort by key first, then by value for duplicate keys
  pairs.sort((a, b) {
    final keyCompare = a.key.compareTo(b.key);
    if (keyCompare != 0) return keyCompare;
    return a.value.compareTo(b.value);
  });
  
  return pairs
      .map((pair) => '${_encodeRFC3986(pair.key)}=${_encodeRFC3986(pair.value)}')
      .join('&');
}
