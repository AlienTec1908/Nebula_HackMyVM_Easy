# Nebula - HackMyVM (Easy)

![Nebula.png](Nebula.png)

## Übersicht

*   **VM:** Nebula
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Nebula)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2024-04-27
*   **Original-Writeup:** https://alientec1908.github.io/Nebula_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Nebula" zu erlangen. Der Weg dorthin begann mit der Entdeckung einer Webanwendung und der Identifizierung einer SQL-Injection-Schwachstelle, die das Auslesen von Benutzerdaten (Benutzernamen und MD5-Passwort-Hashes) aus der Datenbank `nebuladb` ermöglichte. Der Hash für den Benutzer `pmccentral` konnte geknackt werden (`999999999`), was einen SSH-Login erlaubte. Die erste Rechteausweitung zum Benutzer `laboratoryadmin` gelang durch Ausnutzung einer unsicheren `sudo`-Regel, die `pmccentral` erlaubte, `/usr/bin/awk` als `laboratoryadmin` auszuführen. Die finale Eskalation zu Root erfolgte durch Ausnutzung eines Skripts (`/home/laboratoryadmin/autoScripts/PMCEmployees`), das entweder selbst mit erhöhten Rechten lief oder durch Path Hijacking dazu gebracht wurde, Code als Root auszuführen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` / `nano`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `sqlmap`
*   `ssh`
*   `sudo`
*   `awk`
*   Standard Linux-Befehle (`ls`, `cat`, `find`, `id`, `cd`, `grep`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Nebula" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.110) mit `arp-scan` identifiziert. Hostname `nebula.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.2p1) und Port 80 (HTTP, Apache 2.4.41) mit dem Titel "Nebula Lexus Labs".
    *   `gobuster` fand `index.php`, `/login/` und `/joinus/`.
    *   Auf der `/joinus/`-Seite wurde ein Link zu `application_form.pdf` gefunden.
    *   Die PDF-Datei enthielt einen Link (`https://nebulalabs.org/meetings?user=admin&password=d46df8e6a5627debf930f7b5c8f3b083`) mit einem MD5-Hash für den `admin`-Benutzer.
    *   Nach (angenommenem) Login als `admin` wurde auf dem Dashboard der Benutzer `pmccentral` (Rolle "Security") entdeckt.

2.  **Initial Access (SQL Injection & SSH als `pmccentral`):**
    *   Eine SQL-Injection-Schwachstelle wurde (vermutlich auf einer Seite im `/login/`-Bereich oder `meeting_room.php`) mittels `sqlmap` identifiziert (GET-Parameter `id`).
    *   Aus der Datenbank `nebuladb` wurde die Tabelle `users` gedumpt. Diese enthielt MD5-Passwort-Hashes.
    *   Der Hash für den Benutzer `pmccentral` (`c8c605999f3d8352d7bb792cf3fdb25b`) wurde von `sqlmap` zu `999999999` geknackt.
    *   Erfolgreicher SSH-Login als `pmccentral` mit dem Passwort `999999999`.

3.  **Privilege Escalation (von `pmccentral` zu `laboratoryadmin` via `sudo awk`):**
    *   `sudo -l` als `pmccentral` zeigte, dass der Befehl `/usr/bin/awk` als Benutzer `laboratoryadmin` ausgeführt werden durfte: `(laboratoryadmin) /usr/bin/awk`.
    *   Mittels `sudo -u laboratoryadmin awk 'BEGIN {system("/bin/sh")}'` wurde eine Shell als Benutzer `laboratoryadmin` erlangt.
    *   Die User-Flag (`flag{$udeR$_Pr!V11E9E_I5_7En53}`) wurde in `/home/laboratoryadmin/user.txt` gefunden.

4.  **Privilege Escalation (von `laboratoryadmin` zu `root` via Skript Exploit):**
    *   Im Verzeichnis `/home/laboratoryadmin/autoScripts/` wurde das Skript `PMCEmployees` gefunden.
    *   Die `PATH`-Umgebungsvariable wurde manipuliert, um das aktuelle Verzeichnis an den Anfang zu setzen (`PATH=$(pwd):$PATH`).
    *   Durch Ausführen von `./PMCEmployees` wurde eine Root-Shell erhalten. Der genaue Mechanismus (Path Hijacking eines vom Skript aufgerufenen Befehls oder SUID auf dem Skript selbst) wurde im Bericht nicht detailliert.
    *   Die Root-Flag (`flag{r00t_t3ns0}`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Information Disclosure (Credentials in PDF):** Ein MD5-Hash für den `admin`-Benutzer wurde in einer öffentlich zugänglichen PDF-Datei gefunden.
*   **SQL Injection:** Eine Webanwendung war anfällig für SQL-Injection, was das Auslesen von Benutzerdaten und Passwort-Hashes (MD5) aus der Datenbank ermöglichte.
*   **Verwendung schwacher Passwort-Hashes (MD5):** Passwörter wurden als MD5-Hashes gespeichert, die leicht zu knacken sind.
*   **Schwache Passwörter:** Das Passwort `999999999` für `pmccentral` konnte durch `sqlmap`s integrierte Wörterbuchfunktion geknackt werden.
*   **Unsichere `sudo`-Regeln:**
    *   `pmccentral` durfte `awk` als `laboratoryadmin` ausführen. Dies wurde missbraucht, um eine Shell als dieser Benutzer zu erhalten.
*   **Potenzielles Path Hijacking / Unsicheres Skript:** Ein Skript (`PMCEmployees`), das von `laboratoryadmin` ausgeführt werden konnte, führte (ggf. durch Path Hijacking) zu Root-Rechten.

## Flags

*   **User Flag (`/home/laboratoryadmin/user.txt`):** `flag{$udeR$_Pr!V11E9E_I5_7En53}`
*   **Root Flag (`/root/root.txt`):** `flag{r00t_t3ns0}`

## Tags

`HackMyVM`, `Nebula`, `Easy`, `Information Disclosure`, `SQL Injection`, `MD5 Hashes`, `Password Cracking`, `sudo Exploit`, `awk Exploit`, `Path Hijacking`, `Linux`, `Web`, `Privilege Escalation`, `Apache`, `MySQL`
