# -*- coding: utf-8 -*-
"""
EKONZO — lanceur Android (Kivy).
Démarre le serveur Ekonzo en local (127.0.0.1, invisible depuis l'extérieur) puis
affiche l'interface dans une WebView plein écran. Sur PC : ouvre simplement le navigateur.
"""
import os
import threading

from kivy.app import App
from kivy.uix.label import Label
from kivy.utils import platform

_refs = []

if platform == "android":
    from android.runnable import run_on_ui_thread
    from jnius import PythonJavaClass, autoclass, java_method

    PythonActivity = autoclass("org.kivy.android.PythonActivity")
    WebView = autoclass("android.webkit.WebView")
    WebViewClient = autoclass("android.webkit.WebViewClient")
    WebChromeClient = autoclass("android.webkit.WebChromeClient")

    class Retour(PythonJavaClass):
        """Bouton Retour : met l'application en arrière-plan au lieu de la fermer."""
        __javainterfaces__ = ["android/view/View$OnKeyListener"]
        __javacontext__ = "app"

        @java_method("(Landroid/view/View;ILandroid/view/KeyEvent;)Z")
        def onKey(self, vue, code, event):
            if code == 4:
                if event.getAction() == 1:
                    PythonActivity.mActivity.moveTaskToBack(True)
                return True
            return False

    @run_on_ui_thread
    def afficher_webview(url):
        activity = PythonActivity.mActivity
        wv = WebView(activity)
        s = wv.getSettings()
        s.setJavaScriptEnabled(True)
        s.setDomStorageEnabled(True)
        s.setUserAgentString(s.getUserAgentString() + " EkonzoApp")
        wv.setWebViewClient(WebViewClient())
        wv.setWebChromeClient(WebChromeClient())
        try:
            ecouteur = Retour()
            _refs.append(ecouteur)
            wv.setOnKeyListener(ecouteur)
        except Exception:
            pass
        activity.setContentView(wv)
        wv.requestFocus()
        wv.loadUrl(url)
        _refs.append(wv)


class EkonzoApp(App):
    def build(self):
        os.environ["EKONZO_DATA"] = self.user_data_dir      # base de données privée, conservée aux mises à jour
        import ekonzo_web
        self.srv = ekonzo_web.serveur(0, local=True)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return Label(text="Ekonzo démarre…")

    def on_start(self):
        if platform == "android":
            afficher_webview(self.url)
        else:
            import webbrowser
            webbrowser.open(self.url)

    def on_pause(self):
        return True


if __name__ == "__main__":
    EkonzoApp().run()
