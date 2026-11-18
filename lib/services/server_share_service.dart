import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class ServerShareException implements Exception {
  const ServerShareException(this.message);
  final String message;

  @override
  String toString() => 'ServerShareException: $message';
}

class ServerShare {
  const ServerShare({
    required this.id,
    required this.url,
    required this.revokeToken,
    required this.expiresAt,
    this.revokeTokenSaved = true,
  });

  final String id;
  final String url;
  final String revokeToken;
  final DateTime expiresAt;
  final bool revokeTokenSaved;

  ServerShare withRevokeTokenSaved(bool saved) => ServerShare(
        id: id,
        url: url,
        revokeToken: revokeToken,
        expiresAt: expiresAt,
        revokeTokenSaved: saved,
      );

  Map<String, Object?> toJson() => {
        'id': id,
        'url': url,
        'revokeToken': revokeToken,
        'expiresAt': expiresAt.toUtc().toIso8601String(),
      };

  factory ServerShare.fromJson(Map<String, dynamic> json) {
    return ServerShare(
      id: json['id'] as String,
      url: json['url'] as String,
      revokeToken: json['revokeToken'] as String,
      expiresAt: DateTime.parse(json['expiresAt'] as String),
    );
  }
}

/// Server-backed, browser-openable shares. The master encryption key never
/// enters the app; only the short-lived management token is stored locally.
class ServerShareService {
  ServerShareService({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  static const String _configuredBaseUrl = String.fromEnvironment(
    'LINKLOCK_API_BASE',
    defaultValue: '',
  );
  static const String _sharesKey = 'linklock_server_shares_v2';
  static const String _legacyLatestShareKey = 'linklock_latest_server_share_v1';
  static const int _maximumSavedShares = 100;
  static const Duration defaultLifetime = Duration(days: 7);

  final FlutterSecureStorage _storage;

  Uri? get _baseUri {
    final value = _configuredBaseUrl.trim().replaceFirst(RegExp(r'/+$'), '');
    if (value.isEmpty) return null;
    final uri = Uri.tryParse(value);
    if (uri == null || uri.host.isEmpty || uri.userInfo.isNotEmpty) return null;
    if (uri.scheme != 'https') return null;
    if (uri.path.isNotEmpty && uri.path != '/') return null;
    if (uri.hasQuery || uri.hasFragment) return null;
    return uri;
  }

  bool get isConfigured => _baseUri != null;

  Future<ServerShare> createShare(
    String destination, {
    Duration lifetime = defaultLifetime,
  }) async {
    final base = _baseUri;
    if (base == null) {
      throw const ServerShareException(
        'مشاركة الويب غير مفعّلة. لازم إعداد عنوان خادم LinkLock أولًا.',
      );
    }
    final seconds = lifetime.inSeconds;
    if (seconds < 3600 || seconds > 30 * 24 * 3600) {
      throw const ServerShareException('مدة المشاركة لازم تكون من ساعة إلى 30 يوم.');
    }

    final data = await _request(
      'POST',
      base.resolve('/api/shares'),
      body: {'url': destination.trim(), 'ttlSeconds': seconds},
    );

    late ServerShare share;
    try {
      share = ServerShare(
        id: data['id'] as String,
        url: data['shareUrl'] as String,
        revokeToken: data['revokeToken'] as String,
        expiresAt: DateTime.parse(data['expiresAt'] as String),
      );
      final shareUri = Uri.parse(share.url);
      final pathMatch = RegExp(
        r'^/s/([A-Za-z0-9_-]{24})\.([A-Za-z0-9_-]{1,32})\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{20,3800})$',
      ).firstMatch(shareUri.path);
      final shareIdMatches = pathMatch?.group(1) == share.id;
      if (shareUri.scheme != base.scheme ||
          shareUri.host != base.host ||
          shareUri.port != base.port ||
          shareUri.userInfo.isNotEmpty ||
          shareUri.hasQuery ||
          shareUri.hasFragment ||
          share.url.length > 4096 ||
          !shareIdMatches ||
          !RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(share.revokeToken)) {
        throw const FormatException('Unexpected share response values');
      }
    } catch (_) {
      throw const ServerShareException('الخادم رجّع بيانات مشاركة غير صالحة.');
    }
    try {
      final existing = await loadShares();
      final updated = <ServerShare>[
        share,
        ...existing.where((item) => item.id != share.id),
      ].take(_maximumSavedShares).toList(growable: false);
      await _writeShares(updated);
    } catch (_) {
      // The share remains usable for this session, but its management token
      // could not be persisted securely and may be lost after app restart.
      share = share.withRevokeTokenSaved(false);
    }
    return share;
  }

  Future<void> revokeShare(ServerShare share) async {
    if (!RegExp(r'^[A-Za-z0-9_-]{24}$').hasMatch(share.id) ||
        !RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(share.revokeToken)) {
      throw const ServerShareException('بيانات إلغاء المشاركة غير صالحة.');
    }
    final base = _baseUri;
    if (base == null) {
      throw const ServerShareException('عنوان خادم LinkLock غير مضبوط.');
    }
    await _request(
      'DELETE',
      base.resolve('/api/shares/${Uri.encodeComponent(share.id)}'),
      bearerToken: share.revokeToken,
    );
    final existing = await loadShares();
    await _writeShares(existing.where((item) => item.id != share.id).toList());
  }

  /// Loads every locally managed share, newest first. The revoke tokens live
  /// only in platform secure storage; this list is not uploaded to the server.
  Future<List<ServerShare>> loadShares() async {
    try {
      final value = await _storage.read(key: _sharesKey);
      if (value == null || value.isEmpty) {
        // Preserve the single-share token created by earlier app versions.
        final legacy = await _storage.read(key: _legacyLatestShareKey);
        if (legacy == null || legacy.isEmpty) return <ServerShare>[];
        final oldShare = ServerShare.fromJson(
          jsonDecode(legacy) as Map<String, dynamic>,
        );
        if (!oldShare.expiresAt.isAfter(DateTime.now())) {
          await _storage.delete(key: _legacyLatestShareKey);
          return <ServerShare>[];
        }
        await _writeShares(<ServerShare>[oldShare]);
        await _storage.delete(key: _legacyLatestShareKey);
        return <ServerShare>[oldShare];
      }
      final decoded = jsonDecode(value);
      if (decoded is! List) return <ServerShare>[];
      final shares = <ServerShare>[];
      for (final item in decoded) {
        if (item is! Map<String, dynamic>) continue;
        try {
          final share = ServerShare.fromJson(item);
          if (RegExp(r'^[A-Za-z0-9_-]{24}$').hasMatch(share.id) &&
              RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(share.revokeToken) &&
              share.expiresAt.isAfter(DateTime.now())) {
            shares.add(share);
          }
        } catch (_) {
          // Ignore one corrupt record without losing all other revoke tokens.
        }
      }
      return shares.take(_maximumSavedShares).toList(growable: false);
    } catch (_) {
      throw const ServerShareException('تعذر قراءة سجل روابط المشاركة الآمن.');
    }
  }

  Future<void> _writeShares(List<ServerShare> shares) async {
    await _storage.write(
      key: _sharesKey,
      value: jsonEncode(shares.map((share) => share.toJson()).toList()),
    );
  }

  Future<Map<String, dynamic>> _request(
    String method,
    Uri uri, {
    Map<String, Object?>? body,
    String? bearerToken,
  }) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    try {
      final request = await client.openUrl(method, uri).timeout(
            const Duration(seconds: 12),
          );
      request.headers.set(HttpHeaders.acceptHeader, 'application/json');
      if (body != null) {
        request.headers.contentType = ContentType.json;
        request.add(utf8.encode(jsonEncode(body)));
      }
      if (bearerToken != null) {
        request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $bearerToken');
      }

      final response = await request.close().timeout(const Duration(seconds: 15));
      if (response.contentLength > 8192) {
        throw const ServerShareException('استجابة الخادم أكبر من المتوقع.');
      }
      final responseBytes = BytesBuilder(copy: false);
      var receivedBytes = 0;
      await for (final chunk in response.timeout(const Duration(seconds: 10))) {
        receivedBytes += chunk.length;
        if (receivedBytes > 8192) {
          throw const ServerShareException('استجابة الخادم أكبر من المتوقع.');
        }
        responseBytes.add(chunk);
      }
      Map<String, dynamic> data;
      try {
        data = jsonDecode(utf8.decode(responseBytes.takeBytes())) as Map<String, dynamic>;
      } catch (_) {
        throw const ServerShareException('استجابة الخادم غير مفهومة.');
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        final message = data['error'];
        throw ServerShareException(
          message is String ? message : 'الخادم رفض الطلب (${response.statusCode}).',
        );
      }
      return data;
    } on TimeoutException {
      throw const ServerShareException('الاتصال بالخادم استغرق وقتًا طويلًا.');
    } on SocketException {
      throw const ServerShareException('مفيش اتصال بالخادم. راجع الإنترنت وعنوان الخادم.');
    } on HttpException {
      throw const ServerShareException('حصل خطأ في اتصال HTTPS بالخادم.');
    } finally {
      client.close(force: true);
    }
  }
}
