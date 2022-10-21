package com.clocworks.webpush.cli.handlers;

import com.clocworks.webpush.notification.Notification;
import com.clocworks.webpush.push.PushService;
import com.clocworks.webpush.push.Subscription;
import com.clocworks.webpush.cli.commands.SendNotificationCommand;

public class SendNotificationHandler implements HandlerInterface {
    private SendNotificationCommand sendNotificationCommand;

    public SendNotificationHandler(SendNotificationCommand sendNotificationCommand) {
        this.sendNotificationCommand = sendNotificationCommand;
    }

    @Override
    public void run() throws Exception {
        PushService pushService = new PushService()
            .setPublicKey(sendNotificationCommand.getPublicKey())
            .setPrivateKey(sendNotificationCommand.getPrivateKey())
            .setSubject("mailto:admin@domain.com");

        Subscription subscription = sendNotificationCommand.getSubscription();

        Notification notification = new Notification(subscription, sendNotificationCommand.getPayload());

        pushService.send(notification, System.out::println, Throwable::printStackTrace);


    }
}
