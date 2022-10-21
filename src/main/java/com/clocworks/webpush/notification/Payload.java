package com.clocworks.webpush.notification;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@SuppressWarnings("unused")
public class Payload {

    private String  title;
    private String  dir;
    private String  lang;
    private String  body;
    private String  tag;
    private String  image;
    private String  icon;
    private String  badge;
    private List<Long> vibrate = new ArrayList<>();
    private long timestamp = 0;
    private boolean renotify = false;
    private boolean silent = false;
    private boolean requireInteraction = false;
    private String data;

    private List<Action> actions = new ArrayList<>();

//  [SameObject] private String FrozenArray<NotificationAction> actions;

    public Payload(String title) {
        this.title = title;
    }

    public Payload setTitle(String title) {
        this.title = title;
        return this;
    }

    public Payload setDir(String dir) {
        this.dir = dir;
        return this;
    }

    public Payload setLang(String lang) {
        this.lang = lang;
        return this;
    }

    public Payload setBody(String body) {
        this.body = body;
        return this;
    }

    public Payload setTag(String tag) {
        this.tag = tag;
        return this;
    }

    public Payload setImage(String image) {
        this.image = image;
        return this;
    }

    public Payload setIcon(String icon) {
        this.icon = icon;
        return this;
    }

    public Payload setBadge(String badge) {
        this.badge = badge;
        return this;
    }

    public Payload setVibrate(Long[] vibrate) {
        this.vibrate = Arrays.asList(vibrate);
        return this;
    }

    public Payload setTimestamp(long timestamp) {
        this.timestamp = timestamp;
        return this;
    }

    public Payload setRenotify(boolean renotify) {
        this.renotify = renotify;
        return this;
    }

    public Payload setSilent(boolean silent) {
        this.silent = silent;
        return this;
    }

    public Payload setRequireInteraction(boolean requireInteraction) {
        this.requireInteraction = requireInteraction;
        return this;
    }

    public Payload setData(String data) {
        this.data = data;
        return this;
    }

    public Payload setActions(Action... actions) {
        this.actions = Arrays.asList(actions);
        return this;
    }

    public Payload addAction(Action action) {
        this.actions.add(action);
        return this;
    }

    @Override
    public String toString() {
        List<String> attributes = new ArrayList<>();

        if(title != null) attributes.add("\"title\": \"" + title + "\"" );
        if(actions != null) {
            attributes.add("\"actions\": [" + actions.stream().map(Action::getHeader).collect(Collectors.joining(",")) + "]");

            List<String> onActionClick = actions
                    .stream()
                    .map(action -> "\"" + action.getName() + "\":" + action.getOnClick())
                    .collect(Collectors.toList());
            data = "{\"onActionClick\": {" + String.join(",", onActionClick) + "}}";

        }
        if(dir != null) attributes.add("\"dir\": \"" + dir +  "\"");
        if(lang != null) attributes.add("\"lang\": \"" + lang +  "\"");
        if(body != null) attributes.add("\"body\": \"" + body +  "\"");
        if(tag != null) attributes.add("\"tag\":  \"" + tag +  "\"");
        if(image != null) attributes.add("\"image\": \"" + image +  "\"");
        if(icon != null) attributes.add("\"icon\": \"" + icon +  "\"");
        if(badge != null) attributes.add("\"badge\": \"" + badge +  "\"");
        if(vibrate.size() > 0) attributes.add("\"vibrate\" : \"" + vibrate.stream().map(Object::toString).collect(Collectors.joining(",")) + "\"" );
        if(timestamp >0 ) attributes.add("\"timestamp\" : \"" + timestamp +  "\"");
        if(renotify) attributes.add("\"renotify\": true");
        if(silent) attributes.add("\"silent\": \" true");
        if(requireInteraction) attributes.add("\"requireInteraction\": true" );
        if(data != null) attributes.add("\"data\": " + data );


        return "{\"notification\": {" + String.join(",", attributes) + "}}";

    }
}
