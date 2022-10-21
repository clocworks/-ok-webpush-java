package com.clocworks.webpush.notification;

@SuppressWarnings("unused")
public enum Operation {
    openWindow,//	Opens a new tab at the specified URL.
    focusLastFocusedOrOpen, 	//Focuses the last focused client. If there is no client open, then it opens a new tab at the specified URL.
    navigateLastFocusedOrOpen ,	//Focuses the last focused client and navigates it to the specified URL. If there is no client open, then it opens a new tab at the specified URL.
    sendRequest //	Send a simple GET request to the specified URL.
}
