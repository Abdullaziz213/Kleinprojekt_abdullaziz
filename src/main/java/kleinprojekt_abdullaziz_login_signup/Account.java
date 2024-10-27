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
         createTable("User", "user_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE");
 
         // Tabelle "Password_Hashes" erstellen
         createTable("Password_Hashes", "user_id INTEGER, password_hash TEXT, FOREIGN KEY(user_id) REFERENCES User(user_id)");
 
         // Tabelle "Salt" erstellen
         createTable("Salt", "user_id INTEGER, salt TEXT, FOREIGN KEY(user_id) REFERENCES User(user_id)");
 
         // Tabelle "Pepper" erstellen, mit nur einem Wert
         createTable("Pepper", "Pepper_value TEXT");
 
         // Einmalige Speicherung des Pepper-Wertes
         if (getValue("Pepper", "Pepper_value", "1", "Pepper_value") == null) {
             String pepper = generateRandomValue();
             insert("Pepper", "Pepper_value", "'" + pepper + "'");
         }
     }
 
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
         String pepper = getValue("Pepper", "Pepper_value", "1", "Pepper_value");
 
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
 
     // Überprüft, ob das eingegebene Passwort mit dem gespeicherten übereinstimmt
     public boolean verifyPassword(String userName, String password) {
         String userId = getValue("User", "username", "'" + userName + "'", "user_id");
         if (userId == null) {
             System.out.println("Benutzername '" + userName + "' existiert nicht.");
             return false;
         }
 
         String salt = getValue("Salt", "user_id", userId, "salt");
         String pepper = getValue("Pepper", "Pepper_value", "1", "Pepper_value");
         String storedHash = getValue("Password_Hashes", "user_id", userId, "password_hash");
 
         // Passwort-Hash mit Salt und Pepper generieren und überprüfen
         try {
             MessageDigest md = MessageDigest.getInstance("SHA-256");
             md.update((salt + password + pepper).getBytes());
             String calculatedHash = Base64.getEncoder().encodeToString(md.digest());
             return storedHash != null && storedHash.equals(calculatedHash);
         } catch (NoSuchAlgorithmException e) {
             System.out.println("Fehler beim Hashen des Passworts: " + e.getMessage());
             return false;
         }
     }
 
     // Generiert einen zufälligen Salt- oder Pepper-Wert
     private String generateRandomValue() {
         SecureRandom random = new SecureRandom();
         byte[] salt = new byte[16];
         random.nextBytes(salt);
         return Base64.getEncoder().encodeToString(salt);
     }
 }

