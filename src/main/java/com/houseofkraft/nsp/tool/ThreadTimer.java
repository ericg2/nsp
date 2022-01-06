package com.houseofkraft.nsp.tool;

/*
 * Non-Blocking Threaded Timer for NSP
 * Copyright (c) 2022 houseofkraft
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for specific language governing permissions and
 * limitations under the License.
 */

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

public class ThreadTimer {
    private long timeSeconds;
    private final ArrayList<ThreadTimer.TimerListener> listeners = new ArrayList<>();

    public ThreadTimer(long seconds) { setSeconds(seconds); }
    public ThreadTimer() {}

    public ThreadTimer setSeconds(long seconds) { this.timeSeconds = seconds; return this; }
    public ThreadTimer addListener(TimerListener listener) { this.listeners.add(listener); return this; }
    public ThreadTimer startTimer() { new TimerScheduler(timeSeconds, listeners).start(); return this; }

    public interface TimerListener {
        void timerComplete() throws GeneralSecurityException, IOException;
        void timerError(String errorCode);
    }
}


class TimerScheduler extends Thread {
    private final long seconds;
    private final ArrayList<ThreadTimer.TimerListener> listeners;

    public TimerScheduler(long seconds, ArrayList<ThreadTimer.TimerListener> listeners) {
        this.seconds = seconds;
        this.listeners = listeners;
    }

    @Override
    public void run() {
        try {
            TimeUnit.SECONDS.sleep(seconds);
            for (ThreadTimer.TimerListener listener: listeners) {
                listener.timerComplete();
            }
        } catch (InterruptedException | GeneralSecurityException | IOException e) {
            for (ThreadTimer.TimerListener listener: listeners) {
                listener.timerError(e.toString());
            }
        }
    }
}
