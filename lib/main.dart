import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:shared_preferences/shared_preferences.dart';

const Color kSlate = Color(0xFF333B4C);
const Color kBg = Color(0xFFE6E6E6);

void main() => runApp(const CsoVpnApp());

class CsoVpnApp extends StatelessWidget {
  const CsoVpnApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CSO VPN',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorSchemeSeed: kSlate,
        scaffoldBackgroundColor: kBg,
      ),
      home: const HomePage(),
    );
  }
}

// ---------------------------------------------------------------------------
// Compte (un serveur enregistré)
// ---------------------------------------------------------------------------

class Account {
  Account({
    required this.proto,
    this.id = '',
    this.method = 'aes-256-gcm',
    this.server = '',
    this.port = '',
    this.net = 'tcp',
    this.tls = false,
    this.sni = '',
    this.host = '',
    this.path = '',
    this.raw,
  });

  String proto; // vmess, vless, trojan, ss
  String id; // UUID ou mot de passe
  String method; // Shadowsocks seulement
  String server;
  String port;
  String net; // tcp, ws, grpc
  bool tls;
  String sni;
  String host;
  String path; // chemin WebSocket ou nom du service gRPC
  String? raw; // lien complet importé (garde toutes les options)

  String get name => '${proto}_$server';

  Map<String, dynamic> toJson() => {
        'proto': proto,
        'id': id,
        'method': method,
        'server': server,
        'port': port,
        'net': net,
        'tls': tls,
        'sni': sni,
        'host': host,
        'path': path,
        'raw': raw,
      };

  factory Account.fromJson(Map<String, dynamic> j) => Account(
        proto: '${j['proto'] ?? 'vless'}',
        id: '${j['id'] ?? ''}',
        method: '${j['method'] ?? 'aes-256-gcm'}',
        server: '${j['server'] ?? ''}',
        port: '${j['port'] ?? ''}',
        net: '${j['net'] ?? 'tcp'}',
        tls: j['tls'] == true,
        sni: '${j['sni'] ?? ''}',
        host: '${j['host'] ?? ''}',
        path: '${j['path'] ?? ''}',
        raw: j['raw'] as String?,
      );
}

final RegExp _uuidRe = RegExp(
  r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
);

/// Vérifie les champs saisis à la main. Renvoie un message d'erreur ou null.
String? validate(Account a) {
  final isUuid = a.proto == 'vmess' || a.proto == 'vless';
  if (a.server.isEmpty) return 'Indique le serveur.';
  final p = int.tryParse(a.port);
  if (p == null || p < 1 || p > 65535) {
    return 'Le port doit être un nombre entre 1 et 65535.';
  }
  if (a.id.isEmpty) {
    return isUuid ? "Indique l'UUID." : 'Indique le mot de passe.';
  }
  if (isUuid && !_uuidRe.hasMatch(a.id)) {
    return "L'UUID n'est pas valide. Il ressemble à "
        '123e4567-e89b-12d3-a456-426614174000. '
        "Si tu as un lien complet, utilise IMPORTER.";
  }
  return null;
}

Map<String, String> _streamParams(Account a) {
  final sni = a.sni.isNotEmpty ? a.sni : (a.host.isNotEmpty ? a.host : a.server);
  final m = <String, String>{'type': a.net, 'security': a.tls ? 'tls' : 'none'};
  if (a.tls) m['sni'] = sni;
  if (a.net == 'ws') {
    if (a.host.isNotEmpty) m['host'] = a.host;
    if (a.path.isNotEmpty) m['path'] = a.path;
  }
  if (a.net == 'grpc' && a.path.isNotEmpty) m['serviceName'] = a.path;
  return m;
}

String _query(Map<String, String> m) =>
    m.entries.map((e) => '${e.key}=${Uri.encodeQueryComponent(e.value)}').join('&');

/// Construit un lien à partir des champs (avec TLS / WebSocket / gRPC).
String buildLink(Account a) {
  final tag = Uri.encodeComponent('CSO-${a.server}');
  switch (a.proto) {
    case 'vless':
      return 'vless://${Uri.encodeComponent(a.id)}@${a.server}:${a.port}'
          '?encryption=none&${_query(_streamParams(a))}#$tag';
    case 'trojan':
      return 'trojan://${Uri.encodeComponent(a.id)}@${a.server}:${a.port}'
          '?${_query(_streamParams(a))}#$tag';
    case 'vmess':
      {
        final sni =
            a.sni.isNotEmpty ? a.sni : (a.host.isNotEmpty ? a.host : a.server);
        final j = {
          'v': '2',
          'ps': 'CSO-${a.server}',
          'add': a.server,
          'port': a.port,
          'id': a.id,
          'aid': '0',
          'scy': 'auto',
          'net': a.net,
          'type': 'none',
          'host': a.host,
          'path': a.path,
          'tls': a.tls ? 'tls' : '',
          'sni': a.tls ? sni : '',
        };
        return 'vmess://${base64.encode(utf8.encode(jsonEncode(j)))}';
      }
    default:
      {
        final ui = base64Url
            .encode(utf8.encode('${a.method}:${a.id}'))
            .replaceAll('=', '');
        return 'ss://$ui@${a.server}:${a.port}#$tag';
      }
  }
}

String _b64decode(String s) {
  final fixed = s.replaceAll('-', '+').replaceAll('_', '/');
  return utf8.decode(base64.decode(base64.normalize(fixed)));
}

String _normNet(String? n) => (n == 'ws' || n == 'grpc') ? n! : 'tcp';

Account? _parseSs(String link) {
  final body = link.substring(5).split('#').first.split('?').first;
  String userInfo;
  String hostPort;
  if (body.contains('@')) {
    final at = body.lastIndexOf('@');
    userInfo = body.substring(0, at);
    hostPort = body.substring(at + 1);
    if (!userInfo.contains(':')) {
      userInfo = _b64decode(userInfo);
    } else {
      userInfo = Uri.decodeComponent(userInfo);
    }
  } else {
    final decoded = _b64decode(body);
    final at = decoded.lastIndexOf('@');
    if (at < 0) return null;
    userInfo = decoded.substring(0, at);
    hostPort = decoded.substring(at + 1);
  }
  final c = userInfo.indexOf(':');
  final hc = hostPort.lastIndexOf(':');
  if (c < 0 || hc < 0) return null;
  return Account(
    proto: 'ss',
    method: userInfo.substring(0, c),
    id: userInfo.substring(c + 1),
    server: hostPort.substring(0, hc),
    port: hostPort.substring(hc + 1).replaceAll('/', ''),
    raw: link,
  );
}

/// Lit un lien vmess://, vless://, trojan:// ou ss:// (premier lien trouvé).
Account? parseLink(String input) {
  final re = RegExp(r'^(vmess|vless|trojan|ss)://', caseSensitive: false);
  final lines = input.split(RegExp(r'[\r\n]+')).map((l) => l.trim());
  final link = lines.firstWhere((l) => re.hasMatch(l), orElse: () => '');
  if (link.isEmpty) return null;
  final scheme = link.substring(0, link.indexOf('://')).toLowerCase();
  try {
    switch (scheme) {
      case 'vmess':
        {
          final b = link.substring(8).split('#').first;
          final j = jsonDecode(_b64decode(b)) as Map<String, dynamic>;
          return Account(
            proto: 'vmess',
            id: '${j['id'] ?? ''}',
            server: '${j['add'] ?? ''}',
            port: '${j['port'] ?? ''}',
            net: _normNet('${j['net'] ?? 'tcp'}'),
            tls: '${j['tls'] ?? ''}' == 'tls',
            sni: '${j['sni'] ?? ''}',
            host: '${j['host'] ?? ''}',
            path: '${j['path'] ?? ''}',
            raw: link,
          );
        }
      case 'vless':
      case 'trojan':
        {
          final u = Uri.parse(link.split('#').first);
          final q = u.queryParameters;
          return Account(
            proto: scheme,
            id: Uri.decodeComponent(u.userInfo),
            server: u.host,
            port: u.hasPort ? '${u.port}' : '',
            net: _normNet(q['type']),
            tls: q['security'] == 'tls',
            sni: q['sni'] ?? q['peer'] ?? '',
            host: q['host'] ?? '',
            path: q['path'] ?? q['serviceName'] ?? '',
            raw: link,
          );
        }
      case 'ss':
        return _parseSs(link);
    }
  } catch (_) {
    return null;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Profils enregistrés
// ---------------------------------------------------------------------------

Future<List<Account>> loadProfiles() async {
  final p = await SharedPreferences.getInstance();
  return (p.getStringList('profiles') ?? [])
      .map((s) => Account.fromJson(jsonDecode(s) as Map<String, dynamic>))
      .toList();
}

Future<void> saveProfiles(List<Account> list) async {
  final p = await SharedPreferences.getInstance();
  await p.setStringList(
    'profiles',
    list.map((a) => jsonEncode(a.toJson())).toList(),
  );
}

// ---------------------------------------------------------------------------
// Écran principal
// ---------------------------------------------------------------------------

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  late final FlutterVless _vless;
  final _id = TextEditingController();
  final _method = TextEditingController(text: 'aes-256-gcm');
  final _server = TextEditingController();
  final _port = TextEditingController();
  final _sni = TextEditingController();
  final _host = TextEditingController();
  final _path = TextEditingController();

  String _proto = 'vless';
  String _netType = 'tcp';
  bool _tls = false;
  String? _raw;

  String _state = 'DISCONNECTED';
  int _dur = 0;
  int _down = 0;
  int _up = 0;

  bool get _connected => _state == 'CONNECTED';
  bool get _connecting => _state == 'CONNECTING';

  @override
  void initState() {
    super.initState();
    _vless = FlutterVless(onStatusChanged: _onStatus);
  }

  @override
  void dispose() {
    _id.dispose();
    _method.dispose();
    _server.dispose();
    _port.dispose();
    _sni.dispose();
    _host.dispose();
    _path.dispose();
    super.dispose();
  }

  void _onStatus(VlessStatus s) {
    if (!mounted) return;
    setState(() {
      _state = s.state.toUpperCase();
      _dur = s.duration;
      _down = s.downloadSpeed;
      _up = s.uploadSpeed;
    });
  }

  void _msg(String text) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(text)));
  }

  /// Affiche une erreur claire, avec un bouton DÉTAILS pour voir la cause réelle.
  Future<void> _fail(String friendly, Object e) async {
    final details = '$e';
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        SnackBar(
          duration: const Duration(seconds: 12),
          content: Text(friendly),
          action: SnackBarAction(
            label: 'DÉTAILS',
            onPressed: () {
              showDialog<void>(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: const Text('Détails'),
                  content: SingleChildScrollView(child: SelectableText(details)),
                  actions: [
                    TextButton(
                      onPressed: () =>
                          Clipboard.setData(ClipboardData(text: details)),
                      child: const Text('COPIER'),
                    ),
                    TextButton(
                      onPressed: () => Navigator.pop(ctx),
                      child: const Text('FERMER'),
                    ),
                  ],
                ),
              );
            },
          ),
        ),
      );
  }

  Account _current() => Account(
        proto: _proto,
        id: _id.text.trim(),
        method: _method.text.trim().isEmpty ? 'aes-256-gcm' : _method.text.trim(),
        server: _server.text.trim(),
        port: _port.text.trim(),
        net: _netType,
        tls: _tls,
        sni: _sni.text.trim(),
        host: _host.text.trim(),
        path: _path.text.trim(),
        raw: _raw,
      );

  void _fill(Account a) {
    setState(() {
      _proto = a.proto;
      _id.text = a.id;
      _method.text = a.method;
      _server.text = a.server;
      _port.text = a.port;
      _netType = a.net;
      _tls = a.tls;
      _sni.text = a.sni;
      _host.text = a.host;
      _path.text = a.path;
      _raw = a.raw;
    });
  }

  Future<void> _toggle() async {
    if (_connected || _connecting) {
      try {
        await _vless.stopVless();
      } catch (e) {
        await _fail('Impossible de déconnecter.', e);
      }
      return;
    }
    final acc = _current();
    if (acc.raw == null) {
      final err = validate(acc);
      if (err != null) {
        _msg(err);
        return;
      }
    }
    final link = acc.raw ?? buildLink(acc);
    try {
      final parsed = FlutterVless.parse(link);
      await _vless.initializeVless(
        providerBundleIdentifier: 'com.cso.cso_vpn',
        groupIdentifier: 'group.com.cso.cso_vpn',
      );
      if (await _vless.requestPermission()) {
        await _vless.startVless(
          remark: parsed.remark,
          config: parsed.getFullConfiguration(),
        );
      } else {
        _msg('Permission VPN refusée.');
      }
    } catch (e) {
      final text = '$e';
      if (text.contains('INVALID_CONFIG')) {
        await _fail(
          'Configuration refusée. Vérifie UUID / mot de passe, serveur, port, '
          'TLS et WebSocket, ou importe le lien complet.',
          e,
        );
      } else {
        await _fail('Connexion impossible.', e);
      }
    }
  }

  Future<void> _import() async {
    final data = await Clipboard.getData('text/plain');
    final acc = parseLink(data?.text ?? '');
    if (acc == null) {
      _msg('Aucun lien valide dans le presse-papiers.');
      return;
    }
    _fill(acc);
    _msg('Importé : ${acc.proto.toUpperCase()}');
  }

  Future<void> _save() async {
    final acc = _current();
    if (acc.server.isEmpty) {
      _msg('Indique au moins le serveur.');
      return;
    }
    final list = await loadProfiles();
    list.removeWhere((a) => a.name == acc.name);
    list.add(acc);
    await saveProfiles(list);
    _msg('Enregistré !');
  }

  Future<void> _share() async {
    final acc = _current();
    if (acc.raw == null && validate(acc) != null) {
      _msg('Rien à partager : remplis les champs.');
      return;
    }
    await Clipboard.setData(ClipboardData(text: acc.raw ?? buildLink(acc)));
    _msg('Lien copié, tu peux le coller où tu veux.');
  }

  Future<void> _openProfiles() async {
    final picked = await Navigator.push<Account>(
      context,
      MaterialPageRoute(builder: (_) => const ProfilesPage()),
    );
    if (picked != null) _fill(picked);
  }

  String _clock(int s) {
    final d = Duration(seconds: s);
    String two(int n) => n.toString().padLeft(2, '0');
    return '${two(d.inHours)}:${two(d.inMinutes % 60)}:${two(d.inSeconds % 60)}';
  }

  String _kb(int bytesPerSec) => '${(bytesPerSec / 1024).toStringAsFixed(0)} kb/s';

  Widget _field(TextEditingController c, String hint, {TextInputType? type}) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        controller: c,
        keyboardType: type,
        textAlign: TextAlign.center,
        onChanged: (_) => _raw = null,
        style: const TextStyle(
          fontSize: 20,
          fontWeight: FontWeight.w700,
          color: kSlate,
        ),
        decoration: InputDecoration(
          hintText: hint,
          hintStyle: const TextStyle(
            color: Color(0xFF5C5C5C),
            fontWeight: FontWeight.w700,
          ),
          filled: true,
          fillColor: const Color(0xFFF8F8F8),
          contentPadding: const EdgeInsets.symmetric(vertical: 16),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(30),
            borderSide: BorderSide.none,
          ),
        ),
      ),
    );
  }

  Widget _btn(String label, VoidCallback? onTap, {double fs = 18}) {
    return SizedBox(
      height: 52,
      width: double.infinity,
      child: FilledButton(
        onPressed: onTap,
        style: FilledButton.styleFrom(
          backgroundColor: kSlate,
          foregroundColor: Colors.white,
          shape: const StadiumBorder(),
          elevation: 3,
          padding: const EdgeInsets.symmetric(horizontal: 16),
        ),
        child: FittedBox(
          fit: BoxFit.scaleDown,
          child: Text(
            label,
            maxLines: 1,
            style: TextStyle(fontSize: fs, fontWeight: FontWeight.w800),
          ),
        ),
      ),
    );
  }

  Widget _seg(String label, VoidCallback onTap) {
    return Expanded(
      child: TextButton(
        onPressed: onTap,
        style: TextButton.styleFrom(
          foregroundColor: Colors.white,
          minimumSize: const Size.fromHeight(52),
        ),
        child: FittedBox(
          fit: BoxFit.scaleDown,
          child: Text(
            label,
            style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w800),
          ),
        ),
      ),
    );
  }

  Widget _chip(String label, bool selected, VoidCallback onTap) {
    return ChoiceChip(
      label: Text(label),
      selected: selected,
      showCheckmark: false,
      selectedColor: kSlate,
      backgroundColor: Colors.transparent,
      shape: const StadiumBorder(),
      side: const BorderSide(color: kSlate, width: 2),
      labelStyle: TextStyle(
        fontWeight: FontWeight.w800,
        fontSize: 15,
        color: selected ? Colors.white : kSlate,
      ),
      onSelected: (_) => onTap(),
    );
  }

  Widget _stat(IconData icon, String label, String value) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 52,
          height: 52,
          decoration: const BoxDecoration(color: kSlate, shape: BoxShape.circle),
          child: Icon(icon, color: Colors.white, size: 24),
        ),
        const SizedBox(width: 10),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: const TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w700,
                color: Color(0xFF595959),
              ),
            ),
            Text(
              value,
              style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w800),
            ),
          ],
        ),
      ],
    );
  }

  Widget _advanced() {
    return Theme(
      data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
      child: ExpansionTile(
        tilePadding: EdgeInsets.zero,
        childrenPadding: EdgeInsets.zero,
        title: const Text(
          'Options avancées (TLS, WebSocket, SNI…)',
          textAlign: TextAlign.center,
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.w800,
            color: kSlate,
          ),
        ),
        children: [
          Wrap(
            alignment: WrapAlignment.center,
            spacing: 8,
            children: [
              for (final n in const [
                ['tcp', 'TCP'],
                ['ws', 'WebSocket'],
                ['grpc', 'gRPC'],
              ])
                _chip(n[1], _netType == n[0], () {
                  setState(() {
                    _netType = n[0];
                    _raw = null;
                  });
                }),
            ],
          ),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text(
              'TLS (connexion chiffrée)',
              style: TextStyle(fontWeight: FontWeight.w800, color: kSlate),
            ),
            value: _tls,
            onChanged: (v) => setState(() {
              _tls = v;
              _raw = null;
            }),
          ),
          if (_tls) _field(_sni, 'SNI (optionnel)'),
          if (_netType == 'ws') _field(_host, 'Host (optionnel)'),
          if (_netType == 'ws' || _netType == 'grpc')
            _field(
              _path,
              _netType == 'ws' ? 'Chemin (ex. /ws)' : 'Nom du service gRPC',
            ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    const protos = [
      ['vmess', 'VMess'],
      ['vless', 'VLESS'],
      ['trojan', 'Trojan'],
      ['ss', 'Shadowsocks'],
    ];
    final title = _connected
        ? 'Connecté'
        : (_connecting ? 'Connexion…' : 'Déconnecté');
    final titleColor =
        _connected ? const Color(0xFF17692F) : const Color(0xFFC62828);

    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(24, 24, 24, 24),
          child: Column(
            children: [
              Text(
                title,
                style: TextStyle(
                  fontSize: 36,
                  fontWeight: FontWeight.w800,
                  color: titleColor,
                ),
              ),
              Text(
                _clock(_connected ? _dur : 0),
                style: const TextStyle(fontSize: 28, fontWeight: FontWeight.w800),
              ),
              const SizedBox(height: 16),
              Wrap(
                alignment: WrapAlignment.center,
                spacing: 8,
                runSpacing: 4,
                children: [
                  for (final p in protos)
                    _chip(p[1], _proto == p[0], () {
                      setState(() {
                        _proto = p[0];
                        _raw = null;
                        if (p[0] == 'trojan') _tls = true;
                      });
                    }),
                ],
              ),
              const SizedBox(height: 16),
              _field(
                _id,
                (_proto == 'vmess' || _proto == 'vless') ? 'UUID' : 'Mot de passe',
              ),
              if (_proto == 'ss') _field(_method, 'Méthode (ex. aes-256-gcm)'),
              _field(_server, 'Serveur'),
              _field(_port, 'Port', type: TextInputType.number),
              if (_proto != 'ss') _advanced(),
              const SizedBox(height: 4),
              _btn(
                _connected || _connecting ? 'DÉCONNECTER' : 'CONNECTER',
                _toggle,
              ),
              const SizedBox(height: 12),
              Container(
                height: 52,
                decoration: BoxDecoration(
                  color: kSlate,
                  borderRadius: BorderRadius.circular(26),
                ),
                child: Row(
                  children: [
                    _seg('SAUVER', _save),
                    Container(width: 2, height: 52, color: kBg),
                    _seg('PARTAGER', _share),
                    Container(width: 2, height: 52, color: kBg),
                    _seg('PROFILS', _openProfiles),
                  ],
                ),
              ),
              const SizedBox(height: 12),
              _btn('IMPORTER DEPUIS LE PRESSE-PAPIERS', _import, fs: 16),
              const SizedBox(height: 40),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  _stat(Icons.arrow_downward, 'Download', _kb(_connected ? _down : 0)),
                  Container(
                    width: 2,
                    height: 48,
                    margin: const EdgeInsets.symmetric(horizontal: 14),
                    color: const Color(0xFFB5B5B5),
                  ),
                  _stat(Icons.arrow_upward, 'Upload', _kb(_connected ? _up : 0)),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Liste des serveurs
// ---------------------------------------------------------------------------

class ProfilesPage extends StatefulWidget {
  const ProfilesPage({super.key});

  @override
  State<ProfilesPage> createState() => _ProfilesPageState();
}

class _ProfilesPageState extends State<ProfilesPage> {
  List<Account> _list = [];

  @override
  void initState() {
    super.initState();
    loadProfiles().then((l) {
      if (mounted) setState(() => _list = l);
    });
  }

  String _mask(String s) => s.replaceAll(RegExp(r'[A-Za-z0-9_-]'), '*');

  Future<void> _delete(int i) async {
    final next = List<Account>.from(_list)..removeAt(i);
    await saveProfiles(next);
    if (!mounted) return;
    setState(() => _list = next);
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(const SnackBar(content: Text('Supprimé !')));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFFAFAFA),
      body: Column(
        children: [
          Container(
            width: double.infinity,
            padding: EdgeInsets.fromLTRB(
              8,
              MediaQuery.of(context).padding.top + 12,
              8,
              32,
            ),
            decoration: const BoxDecoration(
              color: kSlate,
              borderRadius: BorderRadius.vertical(bottom: Radius.circular(56)),
            ),
            child: Row(
              children: [
                IconButton(
                  tooltip: 'Retour',
                  onPressed: () => Navigator.pop(context),
                  icon: const Icon(Icons.arrow_back, color: Colors.white),
                ),
                const Expanded(
                  child: Text(
                    'Liste des serveurs',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 24,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ),
                const SizedBox(width: 48),
              ],
            ),
          ),
          Expanded(
            child: _list.isEmpty
                ? const Center(
                    child: Text(
                      'Aucun serveur enregistré',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w700,
                        color: Color(0xFF595959),
                      ),
                    ),
                  )
                : ListView.separated(
                    itemCount: _list.length,
                    separatorBuilder: (_, __) =>
                        const Divider(height: 1, color: Color(0xFFE0E0E0)),
                    itemBuilder: (context, i) {
                      final a = _list[i];
                      return ListTile(
                        onTap: () => Navigator.pop(context, a),
                        contentPadding:
                            const EdgeInsets.fromLTRB(16, 8, 12, 8),
                        title: Text(
                          a.name,
                          style: const TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.w800,
                            color: Color(0xFF595959),
                          ),
                        ),
                        subtitle: Text(
                          '${a.proto.toUpperCase()} · ${_mask(a.server)}',
                          style: const TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.w700,
                            color: Color(0xFF595959),
                          ),
                        ),
                        trailing: IconButton.filled(
                          tooltip: 'Supprimer',
                          style: IconButton.styleFrom(
                            backgroundColor: kSlate,
                            foregroundColor: Colors.white,
                            minimumSize: const Size(52, 52),
                          ),
                          onPressed: () => _delete(i),
                          icon: const Icon(Icons.delete),
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}
