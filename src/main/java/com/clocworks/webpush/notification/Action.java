package com.clocworks.webpush.notification;

@SuppressWarnings("unused")
public class Action {

    private final String name;
    private final String title;
    private final String operation;
    private final String url;

    public Action(String name, String title,Operation operation, String url ) {
        this.name = name;
        this.title = title;
        this.operation = operation.toString();
        this.url = url;
    }

    public String getHeader() {
        return "{\"action\": \"" + name +"\", " +
                "\"title\": \" " + title + "\"}";
    }

    public String getOnClick() {
        return "{\"operation\": \"" + operation + "\", \"url\": \"" + url + "\"}";
    }

    public String getName() {
        return this.name;
    }

}
