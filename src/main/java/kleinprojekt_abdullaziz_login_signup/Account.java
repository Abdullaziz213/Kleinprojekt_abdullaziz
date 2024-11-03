/*  Account
 *
 *  Copyright (C) 2023  Robert Schoech
 *  
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

 package kleinprojekt_abdullaziz_login_signup;

 import java.security.MessageDigest;
 import java.security.NoSuchAlgorithmException;
 import java.security.SecureRandom;
 import java.util.Base64;
 
 public class Account extends DatabaseAPI {
 
     // Erstellt alle benötigten Tabellen für die Accountverwaltung
     public void initAccount() {
         // Tabelle "User" erstellen
         createTable("User", "user_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, login_attempts INTEGER DEFAULT 0");
 
         // Tabelle "Password_Hashes" erstellen
         createTable("Password_Hashes", "user_id INTEGER, password_hash TEXT, FOREIGN KEY(user_id) REFERENCES User(user_id)");
 
         // Tabelle "Salt" erstellen
         createTable("Salt", "user_id INTEGER, salt TEXT, FOREIGN KEY(user_id) REFERENCES User(user_id)");


     }

     String pepper = "Hallo mein Name ist Abdullaziz";
 
     // Fügt einen neuen Benutzer in die Datenbank hinzu
     public void addAccount(String name, String password) {
         if (isKeyAvailable("User", "username", "'" + name + "'")) {
             System.out.println("Benutzername " + name + " ist bereits vergeben.");
             return;
         }
 
         // Füge Benutzer in die User-Tabelle ein
         insert("User", "username", "'" + name + "'");
         String userId = getValue("User", "username", "'" + name + "'", "user_id");
 
         // Generiere Salt und hole den Pepper-Wert
         String salt = generateRandomValue();
 
         // Passwort-Hash mit Salt und Pepper erzeugen
         try {
             MessageDigest md = MessageDigest.getInstance("SHA-256");
             md.update((salt + password + pepper).getBytes());
             String passwordHash = Base64.getEncoder().encodeToString(md.digest());
 
             // Speichere Salt, Hash und Benutzer-ID
             insert("Password_Hashes", "user_id, password_hash", userId + ", '" + passwordHash + "'");
             insert("Salt", "user_id, salt", userId + ", '" + salt + "'");
         } catch (NoSuchAlgorithmException e) {
             System.out.println("Fehler beim Hashen des Passworts: " + e.getMessage());
         }
 
         System.out.println("Neuer Account für '" + name + "' wurde erfolgreich erstellt.");
     }
 
     // Überprüft, ob der Benutzername in der Datenbank vorhanden ist
     public boolean verifyAccount(String userName) {
         return isKeyAvailable("User", "username", "'" + userName + "'");
     }

     // Erhöht die Anzahl der Login-Versuche für einen Benutzer
     private void incrementLoginAttempts(String userName) {
        String userId = getValue("User", "username", "'" + userName + "'", "user_id");
        if (userId != null) {
            // Aktuelle Anzahl der Login-Versuche abrufen
            String currentAttempts = getValue("User", "user_id", userId, "login_attempts");
            int attempts = currentAttempts != null ? Integer.parseInt(currentAttempts) : 0;
            
            // Anzahl der Login-Versuche um 1 erhöhen
            attempts++;
            
            // Aktualisieren der Anzahl der Login-Versuche in der Datenbank
            insert("User", "login_attempts", Integer.toString(attempts));
            System.out.println("Login attempts for user " + userName + " incremented to " + attempts);
        }
    }

    // Setzt die Anzahl der Login-Versuche für einen Benutzer zurück
    private void resetLoginAttempts(String userName) {
        String userId = getValue("User", "username", "'" + userName + "'", "user_id");
        if (userId != null) {
            // Zurücksetzen der Anzahl der Login-Versuche auf 0
            insert("User", "login_attempts", "0");
            System.out.println("Login attempts for user " + userName + " reset to 0");
        }
    }

    // Holt die Anzahl der Login-Versuche für einen Benutzer
    public int getLoginAttempts(String userName) {
        String attempts = getValue("User", "username", "'" + userName + "'", "login_attempts");
        return attempts != null ? Integer.parseInt(attempts) : 0;
    }

     public boolean isPasswordStrong(String password) {
        // Prüft die Länge, ob eine Zahl und ein Sonderzeichen enthalten sind
        if (password.length() < 8) {
            return false;
        }
        boolean hasNumber = password.matches(".*\\d.*");
        boolean hasSpecialChar = password.matches(".*[!@#$%^&*()-_=+{};:,<.>].*");

        return hasNumber && hasSpecialChar;
    }
 
     // Überprüft, ob das eingegebene Passwort mit dem gespeicherten übereinstimmt
     public boolean verifyPassword(String userName, String password) {
         // Benutzer-ID abrufen
    String userId = getValue("User", "username", "'" + userName + "'", "user_id");
    if (userId == null) {
        System.out.println("Benutzername '" + userName + "' existiert nicht.");
        return false;
    }

    // Salt, gespeicherten Hash und aktuelle Login-Versuche abrufen
    String salt = getValue("Salt", "user_id", userId, "salt");
    String storedHash = getValue("Password_Hashes", "user_id", userId, "password_hash");
    String currentAttempts = getValue("User", "user_id", userId, "login_attempts");
    int attempts = currentAttempts != null ? Integer.parseInt(currentAttempts) : 0;

    // Wenn der Benutzer gesperrt ist, Login blockieren
    if (attempts >= 3) {
        System.out.println("Account ist gesperrt.");
        return false;
    }

    // Passwort-Hash mit Salt und Pepper generieren und überprüfen
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update((salt + password + pepper).getBytes());
        String calculatedHash = Base64.getEncoder().encodeToString(md.digest());

        if (storedHash != null && storedHash.equals(calculatedHash)) {
            // Passwort korrekt -> Login-Versuche zurücksetzen
            resetLoginAttempts(userName);
            return true;
        } else {
            // Wenn das Passwort falsch ist, erhöhen wir die Login-Versuche
            incrementLoginAttempts(userName);
            return false;
        }

    } catch (NoSuchAlgorithmException e) {
        System.out.println("Fehler beim Hashen des Passworts: " + e.getMessage());
        return false;
    }
     }
 
     // Generiert einen zufälligen Salt
     private String generateRandomValue() {
         SecureRandom random = new SecureRandom();
         byte[] salt = new byte[16];
         random.nextBytes(salt);
         return Base64.getEncoder().encodeToString(salt);
     }
 }

