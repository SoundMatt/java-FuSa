package com.soundmatt.jfusa;

import com.soundmatt.jfusa.runtime.Heartbeat;
import com.soundmatt.jfusa.runtime.SafeStateGuard;
import com.soundmatt.jfusa.runtime.Watchdog;
import org.junit.jupiter.api.Test;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class RuntimeTest {

    //fusa:test REQ-RT001
    @Test
    void watchdog_doesNotFire_whenKickedInTime() throws Exception {
        AtomicBoolean fired = new AtomicBoolean(false);
        Watchdog wd = new Watchdog(200, () -> fired.set(true));
        wd.start();
        Thread.sleep(50); wd.kick();
        Thread.sleep(50); wd.kick();
        wd.stop();
        assertFalse(fired.get(), "Watchdog should not fire when kicked");
    }

    //fusa:test REQ-RT001
    @Test
    void watchdog_fires_onTimeout() throws Exception {
        AtomicBoolean fired = new AtomicBoolean(false);
        Watchdog wd = new Watchdog(100, () -> fired.set(true));
        wd.start();
        Thread.sleep(300);
        wd.stop();
        assertTrue(fired.get(), "Watchdog should fire after timeout without kick");
    }

    //fusa:test REQ-RT002
    @Test
    void heartbeat_callsAction() throws Exception {
        AtomicInteger count = new AtomicInteger(0);
        Heartbeat hb = new Heartbeat(50, count::incrementAndGet);
        hb.start();
        Thread.sleep(250);
        hb.stop();
        assertTrue(count.get() >= 2, "Heartbeat should have fired at least twice");
    }

    //fusa:test REQ-RT003
    @Test
    void safeStateGuard_idempotent() {
        AtomicInteger entered = new AtomicInteger(0);
        SafeStateGuard guard = new SafeStateGuard("test-guard");
        guard.onEnter(entered::incrementAndGet);
        guard.enter("test reason 1");
        guard.enter("test reason 2");
        assertEquals(1, entered.get(), "Safe state should only be entered once (idempotent)");
    }

    @Test
    void safeStateGuard_isEntered_afterEnter() {
        SafeStateGuard guard = new SafeStateGuard("test-guard-2");
        assertFalse(guard.isInSafeState());
        guard.enter("reason");
        assertTrue(guard.isInSafeState());
    }

    @Test
    void safeStateGuard_callsAllHandlers() {
        AtomicInteger sum = new AtomicInteger(0);
        SafeStateGuard guard = new SafeStateGuard("multi-handler");
        guard.onEnter(() -> sum.addAndGet(1));
        guard.onEnter(() -> sum.addAndGet(2));
        guard.onEnter(() -> sum.addAndGet(4));
        guard.enter("multi-test");
        assertEquals(7, sum.get(), "All registered handlers should be called");
    }
}
