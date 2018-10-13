
# The JSON configuration syntax for `libovpncli`

## JSON configuration for initialization

This JSON configuration is used when initializing `libovpncli` library.

```
{
	"enable_log" : <true | false>,
	"verbosity": <normal|debug|verbose>,
	"openvpn_path": <OpenVPN binary path>,
	"report_openvpn_log": <true|false>,
	"report_byte_count": <true|false>
}
```

## JSON configuration for VPN connection

```
{
	"profile_path": <OpenVPN profile path>,
	"server_addr": <OpenVPN server address>,
	"protocol": <OpenVPN protocol, TCP|UDP>,
	"port": <OpenVPN server port>,
	"auth_username": <Auth username>,
	"auth_password": <Auth password>
}
```
