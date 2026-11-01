[app]
title = Ekonzo
package.name = ekonzo
package.domain = org.ekonzo
source.dir = .
source.include_exts = py,png,xml
source.exclude_dirs = .github,bin,.buildozer
version = 1.0
requirements = python3,kivy==2.3.0,sqlite3,openssl,pyjnius,android
orientation = portrait
fullscreen = 0
icon.filename = %(source.dir)s/icon.png
presplash.filename = %(source.dir)s/presplash.png
android.presplash_color = #1e3a8a

# Permissions : INTERNET sert uniquement au serveur local (127.0.0.1) de l'application
android.permissions = INTERNET
android.api = 33
android.minapi = 24
android.archs = arm64-v8a, armeabi-v7a
android.accept_sdk_license = True
android.allow_backup = True
# Autorise la WebView à charger http://127.0.0.1 (serveur interne, jamais exposé au réseau)
android.extra_manifest_application_arguments = ./manifest_app_args.xml

[buildozer]
log_level = 2
warn_on_root = 1
