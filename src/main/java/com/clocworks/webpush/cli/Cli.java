package com.clocworks.webpush.cli;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.clocworks.webpush.cli.commands.GenerateKeyCommand;
import com.clocworks.webpush.cli.commands.SendNotificationCommand;
import com.clocworks.webpush.cli.handlers.GenerateKeyHandler;
import com.clocworks.webpush.cli.handlers.SendNotificationHandler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * Command-line interface
 */
public class Cli {
    private static final String GENERATE_KEY = "generate-key";
    private static final String SEND_NOTIFICATION = "send-notification";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        GenerateKeyCommand generateKeyCommand = new GenerateKeyCommand();
        SendNotificationCommand sendNotificationCommand = new SendNotificationCommand();

        JCommander jCommander = JCommander.newBuilder()
                .addCommand(GENERATE_KEY, generateKeyCommand)
                .addCommand(SEND_NOTIFICATION, sendNotificationCommand)
                .build();

        try {
            jCommander.parse(args);

            if (jCommander.getParsedCommand() != null) {
                switch (jCommander.getParsedCommand()) {
                    case GENERATE_KEY:
                        new GenerateKeyHandler(generateKeyCommand).run();
                        break;
                    case SEND_NOTIFICATION:
                        new SendNotificationHandler(sendNotificationCommand).run();
                        break;
                }
            } else {
                jCommander.usage();
            }
        } catch (ParameterException e) {
            e.usage();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
