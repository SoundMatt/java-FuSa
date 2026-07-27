package com.soundmatt.jfusa.runtime;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Reusable runtime safety pattern: periodic heartbeat.
 *
 * <p>Invokes a {@link Runnable} at a fixed period. Can be used to signal
 * liveness to an external watchdog or to implement periodic health checks.
 *
 * <pre>{@code
 * //fusa:req REQ-RT002
 * Heartbeat hb = new Heartbeat(1000, () -> healthMonitor.beat());
 * hb.start();
 * }</pre>
 */
//fusa:req REQ-RT002
public final class Heartbeat {

    private final long periodMs;
    private final Runnable beat;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final ScheduledExecutorService scheduler;
    private ScheduledFuture<?> task;

    public Heartbeat(long periodMs, Runnable beat) {
        if (periodMs <= 0) throw new IllegalArgumentException("periodMs must be > 0");
        if (beat == null)  throw new IllegalArgumentException("beat handler must not be null");
        this.periodMs = periodMs;
        this.beat = beat;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "jfusa-heartbeat");
            t.setDaemon(true);
            return t;
        });
    }

    //fusa:req REQ-RT002
    public synchronized void start() {
        if (running.compareAndSet(false, true)) {
            task = scheduler.scheduleAtFixedRate(beat, periodMs, periodMs, TimeUnit.MILLISECONDS);
        }
    }

    //fusa:req REQ-RT002
    public synchronized void stop() {
        if (running.compareAndSet(true, false)) {
            if (task != null) task.cancel(false);
            scheduler.shutdown();
        }
    }

    public boolean isRunning() { return running.get(); }
}
