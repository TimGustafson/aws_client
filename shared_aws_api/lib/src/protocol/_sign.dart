import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart';

import '../credentials.dart';
import '../utils/query_string.dart';
import 'endpoint.dart' show ServiceMetadata;

/// Encodes a URI path segment according to RFC3986 for AWS SigV4.
///
/// This encodes each path segment separately, preserving the '/' separators.
/// Only unreserved characters (A-Z, a-z, 0-9, -, ., _, ~) remain unencoded.
String _encodeURIPath(String path) {
  if (path.isEmpty) return '/';

  // Split by /, encode each segment, rejoin
  final segments = path.split('/');
  final encoded = segments.map((segment) {
    if (segment.isEmpty) return '';

    final StringBuffer result = StringBuffer();
    final bytes = utf8.encode(segment);

    for (final byte in bytes) {
      // Check if byte represents an unreserved character per RFC3986
      if ((byte >= 0x41 && byte <= 0x5A) || // A-Z
          (byte >= 0x61 && byte <= 0x7A) || // a-z
          (byte >= 0x30 && byte <= 0x39) || // 0-9
          byte == 0x2D || // -
          byte == 0x2E || // .
          byte == 0x5F || // _
          byte == 0x7E) {
        // ~
        result.writeCharCode(byte);
      } else {
        // Percent-encode all other bytes
        result.write('%${byte.toRadixString(16).toUpperCase().padLeft(2, '0')}');
      }
    }

    return result.toString();
  });

  return encoded.join('/');
}

void signAws4HmacSha256({
  required Request rq,
  required ServiceMetadata service,
  required String region,
  required AwsClientCredentials credentials,
}) {
  final date = _currentDateHeader();
  rq.headers['X-Amz-Date'] = date;
  rq.headers['Host'] = rq.url.host;
  rq.headers['x-amz-content-sha256'] ??= sha256.convert(rq.bodyBytes).toString();
  if (credentials.sessionToken != null) {
    rq.headers['X-Amz-Security-Token'] = credentials.sessionToken!;
  }

  // sorted list of key:value header entries
  final canonicalHeaders = rq.headers.keys.map((key) => '${key.toLowerCase()}:${rq.headers[key]!.trim()}').toList()..sort();
  // sorted list of header keys
  final headerKeys = rq.headers.keys.map((s) => s.toLowerCase()).toList()..sort();

  final payloadHash = sha256.convert(rq.bodyBytes).toString();

  // FIXED: Properly encode the URI path
  final canonicalURI = _encodeURIPath(rq.url.path);

  final canonical = [
    rq.method.toUpperCase(),
    canonicalURI, // Use encoded URI path
    canonicalQueryParametersAll(rq.url.queryParametersAll),
    ...canonicalHeaders,
    '',
    headerKeys.join(';'),
    payloadHash,
  ].join('\n');
  final canonicalHash = sha256.convert(utf8.encode(canonical)).toString();

  final credentialList = [
    date.substring(0, 8),
    region,
    service.signingName ?? service.endpointPrefix,
    'aws4_request',
  ];
  const aws4HmacSha256 = 'AWS4-HMAC-SHA256';
  final toSign = [
    aws4HmacSha256,
    date,
    credentialList.join('/'),
    canonicalHash,
  ].join('\n');

  final signingKey = credentialList.fold(utf8.encode('AWS4${credentials.secretKey}'), (List<int> key, String s) {
    final hmac = Hmac(sha256, key);
    return hmac.convert(utf8.encode(s)).bytes;
  });
  final signature = Hmac(sha256, signingKey).convert(utf8.encode(toSign)).toString();

  final auth = '$aws4HmacSha256 '
      'Credential=${credentials.accessKey}/${credentialList.join('/')}, '
      'SignedHeaders=${headerKeys.join(';')}, '
      'Signature=$signature';
  rq.headers['Authorization'] = auth;
}

String _currentDateHeader() {
  final date = DateTime.now().toUtc().toIso8601String().replaceAll('-', '').replaceAll(':', '').split('.').first;
  return '${date}Z';
}
