package kleinprojekt_abdullaziz_login_signup;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextField;

public class AccountController {

    private Account account;
    
    @FXML
    private Button btLogin;
    
    @FXML
    private Button btLogout;

    @FXML
    private Button btSignUp;

    @FXML
    private Label lbLoginMessage;

    @FXML
    private Label lbSignUpMessage;

    @FXML
    private PasswordField pfLoginPassword;

    @FXML
    private PasswordField pfSignUpConfirmPassword;

    @FXML
    private PasswordField pfSignUpPassword;
     
    @FXML
    private TabPane tabPane;

    @FXML
    private TextField tfSignUpEmail;

    @FXML
    private TextField tfUsername;
 
    @FXML
    private void initialize() throws Exception {
        // Account-Objekt erstellen und Datenbanktabellen initialisieren
        account = new Account();
        account.initAccount();
    }   

    @FXML
    private void onSignUp(ActionEvent event) throws Exception {
        // Benutzername, Passwort und bestätigtes Passwort prüfen
        String name = tfSignUpEmail.getText();
        if (name.isEmpty()) {
            lbSignUpMessage.setText("Type in email");
            return;
        }

        String pw = pfSignUpPassword.getText().trim();
        if (pw.isEmpty()) {
            lbSignUpMessage.setText("Enter a plausible password");
            return;
        }

        // Überprüfen, ob das Passwort stark genug ist
        if (!account.isPasswordStrong(pw)) {
            lbSignUpMessage.setText("Password must be at least 8 characters, contain a number and a special character.");
            return;
        }

        if (!pw.equals(pfSignUpConfirmPassword.getText())) {
            lbSignUpMessage.setText("Password and confirmed password are not identical");
            return;
        }

        // Verifizierung des Accounts
        if (account.verifyAccount(name)) {
            lbSignUpMessage.setText("Email " + name + " has already an account");
            return;
        }
        
        // Neuen Account hinzufügen
        account.addAccount(name, pw);
        
        // Tab "Log In" auswählen
        tabPane.getTabs().get(0).setDisable(true);
        
        // Login- und Signup-Felder zurücksetzen
        resetLogin();
        resetSignup();
        
        // Tab "Log in" auswählen
        tabPane.getSelectionModel().select(1);
    }

    @FXML
    private void onLogin(ActionEvent event) {
        String name = tfUsername.getText();
        String pw = pfLoginPassword.getText();
                        
        if (account.verifyPassword(name, pw)) {
            tabPane.getTabs().get(0).setDisable(true);
            tabPane.getTabs().get(1).setDisable(true);
            tabPane.getTabs().get(2).setDisable(false);
            tabPane.getSelectionModel().select(2);
        } else {
            // Zeigt eine gesperrte Meldung an, falls das Konto gesperrt ist
            String attempts = account.getValue("User", "username", "'" + name + "'", "login_attempts");
            if (attempts != null && Integer.parseInt(attempts) >= 3) {
                lbLoginMessage.setText("Account ist gesperrt. Bitte wenden Sie sich an den Support.");
            } else {
                lbLoginMessage.setText("'Email' or 'Password' are wrong");
            }
        }
    }
   
    @FXML
    private void onLogout(ActionEvent event) {
        // Tabs zurücksetzen
        tabPane.getTabs().get(0).setDisable(false);
        tabPane.getTabs().get(1).setDisable(false);
        tabPane.getTabs().get(2).setDisable(true);
        
        // Login zurücksetzen und Tab "Log in" auswählen
        resetLogin();   
        tabPane.getSelectionModel().select(1);      
    }
    
    private void resetLogin() {
        tfUsername.setText("");
        pfLoginPassword.setText("");
        lbLoginMessage.setText("Login with your account");
    } 

    private void resetSignup() {
        tfSignUpEmail.setText("");
        pfSignUpPassword.setText("");
        pfSignUpConfirmPassword.setText("");
        lbSignUpMessage.setText("Create Account");
    }
}
