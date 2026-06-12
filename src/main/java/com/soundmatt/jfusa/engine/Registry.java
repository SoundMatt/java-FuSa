package com.soundmatt.jfusa.engine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Holds a set of registered {@link Rule}s.
 */
//fusa:req REQ-ENG001
public final class Registry {

    private final List<Rule> rules = new ArrayList<>();
    private final Map<String, Rule> index = new LinkedHashMap<>();

    public Registry() {}

    //fusa:req REQ-ENG005
    public void register(Rule r) {
        if (r == null) throw new IllegalArgumentException("engine: cannot register null rule");
        if (index.containsKey(r.id()))
            throw new IllegalStateException("engine: rule \"" + r.id() + "\" already registered");
        rules.add(r);
        index.put(r.id(), r);
    }

    //fusa:req REQ-ENG004
    public void mustRegister(Rule r) {
        try { register(r); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    /** Returns a copy of registered rules sorted by ID. */
    //fusa:req REQ-ENG001
    public List<Rule> rules() {
        List<Rule> out = new ArrayList<>(rules);
        out.sort((a, b) -> a.id().compareTo(b.id()));
        return Collections.unmodifiableList(out);
    }

    public Rule get(String id) { return index.get(id); }
}
