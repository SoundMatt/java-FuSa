package com.soundmatt.jfusa.runtime;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Reusable runtime safety pattern: software watchdog.
 *
 * <p>The watchdog fires a {@link Runnable} handler if {@link #kick()} is not called
 * within {@code timeoutMs} milliseconds. The handler must invoke a safe-state entry
 * point annotated {@code //fusa:safe-state}.
 *
 * <pre>{@code
 * //fusa:req REQ-RT001
 * Watchdog wd = new Watchdog(5000, () -> {
 *     //fusa:safe-state watchdog timeout — enter de-energised state
 *     SafeStateGuard.enterSafeState("watchdog timeout");
 * });
 * wd.start();
 * // In the processing loop:
 * wd.kick(); // reset the timer each cycle
 * }</pre>
 */
//fusa:req REQ-RT001
public final class Watchdog {

    private final long timeoutMs;
    private final Runnable handler;
    private final AtomicLong lastKickMs = new AtomicLong(System.currentTimeMillis());
    private final ScheduledExecutorService scheduler;
    private ScheduledFuture<?> task;

    public Watchdog(long timeoutMs, Runnable handler) {
        if (timeoutMs <= 0) throw new IllegalArgumentException("timeoutMs must be > 0");
        if (handler == null) throw new IllegalArgumentException("handler must not be null");
        this.timeoutMs = timeoutMs;
        this.handler = handler;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "jfusa-watchdog");
            t.setDaemon(true);
            return t;
        });
    }

    /** Start the watchdog timer. */
    public synchronized void start() {
        lastKickMs.set(System.currentTimeMillis());
        long checkIntervalMs = Math.max(timeoutMs / 4, 50);
        task = scheduler.scheduleAtFixedRate(this::check, checkIntervalMs, checkIntervalMs, TimeUnit.MILLISECONDS);
    }

    /** Reset the watchdog timer. Call this from the monitored processing loop. */
    public void kick() {
        lastKickMs.set(System.currentTimeMillis());
    }

    /** Stop the watchdog. */
    public synchronized void stop() {
        if (task != null) task.cancel(false);
        scheduler.shutdown();
    }

    private void check() {
        if (System.currentTimeMillis() - lastKickMs.get() > timeoutMs) {
            stop();
            handler.run();
        }
    }
}
