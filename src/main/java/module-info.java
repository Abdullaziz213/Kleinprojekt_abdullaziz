module kleinprojekt_abdullaziz_login_signup {
    requires javafx.controls;
    requires javafx.fxml;
    requires org.apache.commons.codec;
    requires java.sql;

    opens kleinprojekt_abdullaziz_login_signup to javafx.fxml;
    exports kleinprojekt_abdullaziz_login_signup;
}
