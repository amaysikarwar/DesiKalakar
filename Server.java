/*
 * SkillProof backend  (Java 17+, zero dependencies)
 * Run:  java Server.java        ->  http://localhost:8080
 *
 * Idea: a worker logs a finished job -> the CLIENT gets a code by SMS ->
 * the client confirms (rating + would-hire-again) -> job becomes VERIFIED and is
 * added to the worker's tamper-evident hash chain. A stranger can open the
 * worker's public profile and trust the record because the worker can't
 * confirm his own jobs (the code only goes to the client's phone).
 */
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;

public class Server {

    // ---------- config ----------
    static final int PORT = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
    static final boolean DEV = !"false".equalsIgnoreCase(System.getenv().getOrDefault("DEV", "true")); // DEV: fake SMS inbox exposed
    static final String BASE = System.getenv().getOrDefault("BASE_URL", "http://localhost:" + PORT);
    static final Path DATA = Paths.get(System.getenv().getOrDefault("DATA_FILE", "data/db.json"));
    static final Path PUBLIC = Paths.get("public").toAbsolutePath().normalize();
    static final SecureRandom RNG = new SecureRandom();
    static final Object LOCK = new Object();
    static final List<Map<String, Object>> OUTBOX = new CopyOnWriteArrayList<>(); // fake SMS gateway (dev only)
    static Map<String, Object> db;

    // ---------- small utils ----------
    static class ApiError extends RuntimeException {
        final int status;
        ApiError(int s, String m) { super(m); status = s; }
    }
    static ApiError bad(String m) { return new ApiError(400, m); }

    @SuppressWarnings("unchecked") static Map<String, Object> M(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> L(Object o) { return (List<Object>) o; }
    static String S(Map<String, Object> m, String k) { Object v = m.get(k); return v == null ? "" : String.valueOf(v).trim(); }
    static int I(Map<String, Object> m, String k, int d) {
        Object v = m.get(k);
        if (v instanceof Number n) return n.intValue();
        try { return Integer.parseInt(String.valueOf(v).trim()); } catch (Exception e) { return d; }
    }
    static boolean B(Map<String, Object> m, String k) { Object v = m.get(k); return v instanceof Boolean b ? b : "true".equalsIgnoreCase(String.valueOf(v)); }

    static String sha(String s) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte x : h) sb.append(String.format("%02x", x));
            return sb.toString();
        } catch (Exception e) { throw new RuntimeException(e); }
    }
    static String rid(String prefix) { byte[] b = new byte[5]; RNG.nextBytes(b); StringBuilder sb = new StringBuilder(prefix); for (byte x : b) sb.append(String.format("%02x", x)); return sb.toString(); }
    static String phone(String raw) {
        String d = raw == null ? "" : raw.replaceAll("\\D", "");
        if (d.length() > 10) d = d.substring(d.length() - 10);
        if (d.length() != 10) throw bad("Enter a 10-digit mobile number");
        return d;
    }
    static String mask(String p) { return p.substring(0, 2) + "•••••" + p.substring(7); }
    static String firstName(String n) { String[] t = n.trim().split("\\s+"); return t.length == 0 || t[0].isEmpty() ? "Client" : t[0] + (t.length > 1 ? " " + t[t.length - 1].charAt(0) + "." : ""); }
    static double round1(double x) { return Math.round(x * 10) / 10.0; }

    // ---------- tiny JSON ----------
    static final class Json {
        static String str(Object o) { StringBuilder sb = new StringBuilder(); w(sb, o); return sb.toString(); }
        static void w(StringBuilder sb, Object o) {
            if (o == null) sb.append("null");
            else if (o instanceof String s) {
                sb.append('"');
                for (char c : s.toCharArray()) {
                    switch (c) {
                        case '"' -> sb.append("\\\"");
                        case '\\' -> sb.append("\\\\");
                        case '\n' -> sb.append("\\n");
                        case '\r' -> sb.append("\\r");
                        case '\t' -> sb.append("\\t");
                        default -> { if (c < 0x20) sb.append(String.format("\\u%04x", (int) c)); else sb.append(c); }
                    }
                }
                sb.append('"');
            } else if (o instanceof Number || o instanceof Boolean) sb.append(o);
            else if (o instanceof Map<?, ?> m) {
                sb.append('{'); boolean f = true;
                for (var e : m.entrySet()) { if (!f) sb.append(','); f = false; w(sb, String.valueOf(e.getKey())); sb.append(':'); w(sb, e.getValue()); }
                sb.append('}');
            } else if (o instanceof Collection<?> c) {
                sb.append('['); boolean f = true;
                for (var x : c) { if (!f) sb.append(','); f = false; w(sb, x); }
                sb.append(']');
            } else w(sb, o.toString());
        }
        static Object parse(String s) {
            P p = new P(s); Object v = p.val(); p.ws();
            if (p.i != s.length()) throw new IllegalArgumentException("Trailing data");
            return v;
        }
        static final class P {
            final String s; int i;
            P(String s) { this.s = s; }
            void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
            IllegalArgumentException err() { return new IllegalArgumentException("Invalid JSON at " + i); }
            void expect(char c) { if (i >= s.length() || s.charAt(i) != c) throw err(); i++; }
            Object val() {
                ws();
                if (i >= s.length()) throw err();
                char c = s.charAt(i);
                if (c == '{') {
                    i++; Map<String, Object> m = new LinkedHashMap<>(); ws();
                    if (s.charAt(i) == '}') { i++; return m; }
                    while (true) { ws(); String k = string(); ws(); expect(':'); m.put(k, val()); ws(); char d = s.charAt(i++); if (d == '}') return m; if (d != ',') throw err(); }
                }
                if (c == '[') {
                    i++; List<Object> l = new ArrayList<>(); ws();
                    if (s.charAt(i) == ']') { i++; return l; }
                    while (true) { l.add(val()); ws(); char d = s.charAt(i++); if (d == ']') return l; if (d != ',') throw err(); }
                }
                if (c == '"') return string();
                if (s.startsWith("true", i)) { i += 4; return true; }
                if (s.startsWith("false", i)) { i += 5; return false; }
                if (s.startsWith("null", i)) { i += 4; return null; }
                int st = i;
                while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
                String n = s.substring(st, i);
                if (n.isEmpty()) throw err();
                return (n.contains(".") || n.contains("e") || n.contains("E")) ? (Object) Double.valueOf(n) : (Object) Long.valueOf(n);
            }
            String string() {
                expect('"'); StringBuilder sb = new StringBuilder();
                while (true) {
                    char c = s.charAt(i++);
                    if (c == '"') return sb.toString();
                    if (c == '\\') {
                        char e = s.charAt(i++);
                        switch (e) {
                            case 'n' -> sb.append('\n'); case 't' -> sb.append('\t'); case 'r' -> sb.append('\r');
                            case 'b' -> sb.append('\b'); case 'f' -> sb.append('\f');
                            case 'u' -> { sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                            default -> sb.append(e);
                        }
                    } else sb.append(c);
                }
            }
        }
    }

    // ---------- storage (JSON file; swap for a real DB later) ----------
    static void load() throws IOException {
        if (Files.exists(DATA)) db = M(Json.parse(Files.readString(DATA)));
        else { db = new LinkedHashMap<>(); db.put("workers", new ArrayList<>()); db.put("jobs", new ArrayList<>()); db.put("sessions", new LinkedHashMap<>()); }
    }
    static void save() {
        try {
            Files.createDirectories(DATA.toAbsolutePath().getParent());
            Path tmp = DATA.resolveSibling(DATA.getFileName() + ".tmp");
            Files.writeString(tmp, Json.str(db));
            Files.move(tmp, DATA, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) { throw new RuntimeException(e); }
    }
    static List<Object> workers() { return L(db.get("workers")); }
    static List<Object> jobs() { return L(db.get("jobs")); }
    static Map<String, Object> sessions() { return M(db.get("sessions")); }

    static Map<String, Object> workerById(String id) { for (Object o : workers()) if (S(M(o), "id").equals(id)) return M(o); return null; }
    static Map<String, Object> workerByPhone(String ph) { for (Object o : workers()) if (S(M(o), "phone").equals(ph)) return M(o); return null; }
    static Map<String, Object> jobById(String id) { for (Object o : jobs()) if (S(M(o), "id").equals(id)) return M(o); return null; }
    static List<Map<String, Object>> verifiedJobs(String wid) {
        return jobs().stream().map(Server::M).filter(j -> S(j, "workerId").equals(wid) && S(j, "status").equals("VERIFIED"))
                .sorted(Comparator.comparingInt(j -> I(j, "seq", 0))).collect(Collectors.toList());
    }

    // ---------- domain ----------
    static Map<String, Object> newWorker(String name, String ph, String trade, String city, int years, String pin) {
        Map<String, Object> w = new LinkedHashMap<>();
        String salt = rid("s");
        w.put("id", rid("w_")); w.put("name", name); w.put("phone", ph); w.put("trade", trade); w.put("city", city);
        w.put("claimedYears", years); w.put("salt", salt); w.put("pinHash", sha(salt + pin)); w.put("createdAt", Instant.now().toString());
        workers().add(w);
        return w;
    }
    static Map<String, Object> workerSelf(Map<String, Object> w) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (String k : List.of("id", "name", "phone", "trade", "city", "claimedYears")) o.put(k, w.get(k));
        return o;
    }
    static Map<String, Object> startSession(Map<String, Object> w) {
        String token = rid("t_") + rid("");
        sessions().put(token, S(w, "id")); save();
        Map<String, Object> r = new LinkedHashMap<>(); r.put("token", token); r.put("worker", workerSelf(w)); return r;
    }
    static Map<String, Object> auth(HttpExchange ex) {
        String h = ex.getRequestHeaders().getFirst("Authorization");
        if (h == null || !h.startsWith("Bearer ")) throw new ApiError(401, "Please log in");
        Object wid = sessions().get(h.substring(7).trim());
        Map<String, Object> w = wid == null ? null : workerById(String.valueOf(wid));
        if (w == null) throw new ApiError(401, "Session expired, please log in again");
        return w;
    }

    static Map<String, Object> register(Map<String, Object> b) {
        String name = S(b, "name"), trade = S(b, "trade").toLowerCase(), city = S(b, "city"), pin = S(b, "pin");
        String ph = phone(S(b, "phone")); int yrs = I(b, "claimedYears", 0);
        if (name.length() < 2 || name.length() > 60) throw bad("Enter your name");
        if (trade.isEmpty() || trade.length() > 30) throw bad("Enter your trade, e.g. painter");
        if (city.isEmpty() || city.length() > 40) throw bad("Enter your city");
        if (!pin.matches("\\d{4}")) throw bad("PIN must be 4 digits");
        if (yrs < 0 || yrs > 60) throw bad("Years of experience must be 0-60");
        if (workerByPhone(ph) != null) throw new ApiError(409, "This phone is already registered. Please log in.");
        Map<String, Object> w = newWorker(name, ph, trade, city, yrs, pin);
        return startSession(w);
    }
    static Map<String, Object> login(Map<String, Object> b) {
        Map<String, Object> w = workerByPhone(phone(S(b, "phone")));
        if (w == null || !sha(S(w, "salt") + S(b, "pin")).equals(S(w, "pinHash"))) throw new ApiError(401, "Wrong phone or PIN");
        return startSession(w);
    }

    static void sendSms(String to, String text) {
        Map<String, Object> m = new LinkedHashMap<>(); m.put("to", to); m.put("text", text); m.put("at", Instant.now().toString());
        OUTBOX.add(m);
        System.out.println("[SMS -> " + to + "] " + text);   // real version: call an SMS gateway here
    }

    static Map<String, Object> createJob(Map<String, Object> w, String title, String city, String date, String clientName, String clientPhone, boolean notify) {
        if (title.length() < 3 || title.length() > 100) throw bad("Describe the job in 3-100 characters");
        String cp = phone(clientPhone);
        if (cp.equals(S(w, "phone"))) throw bad("Client's phone cannot be your own phone");
        LocalDate d;
        try { d = date.isEmpty() ? LocalDate.now() : LocalDate.parse(date); } catch (Exception e) { throw bad("Date must look like 2026-10-09"); }
        if (d.isAfter(LocalDate.now())) throw bad("Date cannot be in the future");
        long pending = jobs().stream().map(Server::M).filter(j -> S(j, "workerId").equals(S(w, "id")) && S(j, "status").equals("PENDING")).count();
        if (pending >= 20) throw new ApiError(429, "Too many unconfirmed jobs. Ask clients to confirm first.");
        String id = rid("j_"); String code = String.format("%06d", RNG.nextInt(1_000_000));
        Map<String, Object> j = new LinkedHashMap<>();
        j.put("id", id); j.put("workerId", S(w, "id")); j.put("title", title); j.put("city", city.isEmpty() ? S(w, "city") : city);
        j.put("date", d.toString()); j.put("clientName", clientName.isEmpty() ? "Client" : clientName);
        j.put("clientPhone", cp); j.put("clientKey", sha("client:" + cp));
        j.put("codeHash", sha(code + id));            // the code itself is NEVER stored or returned to the worker
        j.put("status", "PENDING"); j.put("attempts", 0); j.put("createdAt", Instant.now().toString());
        jobs().add(j); save();
        if (notify)
            sendSms(cp, S(w, "name") + " (" + S(w, "trade") + ") says he finished \"" + title + "\" for you on " + d
                    + ". To confirm reply: YES " + code + " <1-5 stars>  or open " + BASE + "/#/verify/" + id + " and enter code " + code + ". Ignore if untrue.");
        return j;
    }

    static String hashOf(String prev, Map<String, Object> j) {
        return sha(prev + "|" + S(j, "workerId") + "|" + S(j, "id") + "|" + S(j, "title") + "|" + S(j, "date") + "|" + S(j, "city") + "|"
                + S(j, "clientKey") + "|" + S(j, "rating") + "|" + S(j, "again") + "|" + S(j, "verifiedAt"));
    }
    static void finish(Map<String, Object> j, int rating, boolean again, String note, String when) {
        if (rating < 1 || rating > 5) throw bad("Rating must be 1 to 5");
        String wid = S(j, "workerId");
        List<Map<String, Object>> v = verifiedJobs(wid);
        String prev = v.isEmpty() ? "GENESIS" : S(v.get(v.size() - 1), "hash");
        j.put("status", "VERIFIED"); j.put("rating", rating); j.put("again", again);
        j.put("note", note.length() > 200 ? note.substring(0, 200) : note);
        j.put("verifiedAt", when); j.put("seq", v.size() + 1); j.put("prevHash", prev); j.put("hash", hashOf(prev, j));
        save();
    }
    static void verify(Map<String, Object> j, String code, int rating, boolean again, String note) {
        if (!S(j, "status").equals("PENDING")) throw new ApiError(409, "This job is already " + S(j, "status").toLowerCase());
        int att = I(j, "attempts", 0);
        if (att >= 5) throw new ApiError(429, "Too many wrong codes. Ask the worker to log the job again.");
        if (!sha(code.trim() + S(j, "id")).equals(S(j, "codeHash"))) { j.put("attempts", att + 1); save(); throw new ApiError(403, "Wrong code (" + (4 - att) + " tries left)"); }
        finish(j, rating, again, note, Instant.now().truncatedTo(ChronoUnit.SECONDS).toString());
    }

    static Map<String, Object> stats(String wid) {
        List<Map<String, Object>> v = verifiedJobs(wid);
        Set<String> clients = new HashSet<>(); Map<String, Integer> per = new HashMap<>();
        double sum = 0; int again = 0; String first = null;
        for (var j : v) {
            String ck = S(j, "clientKey"); clients.add(ck); per.merge(ck, 1, Integer::sum);
            sum += I(j, "rating", 0); if (B(j, "again")) again++;
            String d = S(j, "date"); if (first == null || d.compareTo(first) < 0) first = d;
        }
        int repeat = (int) per.values().stream().filter(c -> c >= 2).count();
        double avg = v.isEmpty() ? 0 : sum / v.size();
        double score = v.isEmpty() ? 0 : Math.min(clients.size() / 10.0, 1) * 50 + Math.min(v.size() / 20.0, 1) * 20 + (avg / 5) * 20 + Math.min(repeat / 3.0, 1) * 10;
        int sc = (int) Math.round(score);
        String level = sc >= 75 ? "Highly trusted" : sc >= 50 ? "Trusted" : sc >= 20 ? "Building record" : "New";
        long pending = jobs().stream().map(Server::M).filter(j -> S(j, "workerId").equals(wid) && S(j, "status").equals("PENDING")).count();
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("verifiedJobs", v.size()); s.put("distinctClients", clients.size()); s.put("repeatClients", repeat);
        s.put("avgRating", round1(avg)); s.put("wouldHireAgain", again); s.put("pendingJobs", pending);
        s.put("provenSince", first == null ? "" : first);
        s.put("provenYears", first == null ? 0.0 : round1(ChronoUnit.DAYS.between(LocalDate.parse(first), LocalDate.now()) / 365.25));
        s.put("score", sc); s.put("level", level);
        s.put("scoreFormula", "50% distinct clients (10 = full) + 20% volume (20 jobs = full) + 20% avg rating + 10% repeat clients (3 = full)");
        return s;
    }
    static Map<String, Object> publicJob(Map<String, Object> j) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (String k : List.of("id", "title", "city", "date", "rating", "again", "note", "verifiedAt", "hash", "prevHash")) o.put(k, j.get(k));
        o.put("client", firstName(S(j, "clientName")));
        return o;
    }
    static Map<String, Object> ownerJob(Map<String, Object> j) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (String k : List.of("id", "title", "city", "date", "status", "rating", "again", "note", "createdAt", "verifiedAt", "hash")) o.put(k, j.get(k));
        o.put("clientName", S(j, "clientName")); o.put("clientPhone", mask(S(j, "clientPhone")));
        return o;
    }
    static Map<String, Object> workerSummary(Map<String, Object> w) {
        Map<String, Object> o = new LinkedHashMap<>(); o.put("id", w.get("id")); o.put("name", w.get("name")); o.put("trade", w.get("trade"));
        o.put("city", w.get("city")); o.put("claimedYears", w.get("claimedYears")); o.put("stats", stats(S(w, "id"))); return o;
    }
    static Map<String, Object> workerProfile(Map<String, Object> w) {
        Map<String, Object> o = workerSummary(w); o.put("phone", w.get("phone"));
        List<Map<String, Object>> v = verifiedJobs(S(w, "id")); Collections.reverse(v);
        o.put("jobs", v.stream().map(Server::publicJob).collect(Collectors.toList())); return o;
    }
    static Map<String, Object> audit(Map<String, Object> w) {
        String prev = "GENESIS"; int n = 0; String broken = null;
        for (var j : verifiedJobs(S(w, "id"))) {
            n++;
            if (!S(j, "prevHash").equals(prev) || !hashOf(prev, j).equals(S(j, "hash"))) { broken = S(j, "id"); break; }
            prev = S(j, "hash");
        }
        Map<String, Object> r = new LinkedHashMap<>(); r.put("valid", broken == null); r.put("checked", n); r.put("brokenAt", broken == null ? "" : broken); r.put("head", prev);
        return r;
    }

    // ---------- SMS interface (for basic phones) ----------
    static String sms(String fromRaw, String text) {
        try {
            String from = phone(fromRaw); String[] t = text.trim().split("\\s+"); String cmd = t[0].toUpperCase();
            Map<String, Object> w = workerByPhone(from);
            switch (cmd) {
                case "REG": {
                    if (t.length < 4) return "To join SMS: REG <name> <trade> <city>   e.g. REG Ramesh painter Pune";
                    if (w != null) return "Already registered. Send JOB <work> <client phone>";
                    String pin = String.format("%04d", RNG.nextInt(10000));
                    newWorker(t[1], from, t[2].toLowerCase(), String.join(" ", Arrays.copyOfRange(t, 3, t.length)), 0, pin); save();
                    return "Welcome " + t[1] + "! Your app PIN is " + pin + ". After a job send: JOB <work> <client phone>";
                }
                case "JOB": {
                    if (w == null) return "Not registered. Send: REG <name> <trade> <city>";
                    if (t.length < 3) return "Send: JOB <work done> <client phone>   e.g. JOB 2BHK wall painting 9876543210";
                    String title = String.join(" ", Arrays.copyOfRange(t, 1, t.length - 1));
                    createJob(w, title, "", "", "", t[t.length - 1], true);
                    return "Saved. We sent a confirm code to the client (" + mask(phone(t[t.length - 1])) + "). Job counts once they reply.";
                }
                case "YES": {
                    if (t.length < 2) return "Reply: YES <code> <1-5 stars>";
                    int rating = t.length > 2 ? I(Map.of("r", t[2]), "r", 5) : 5;
                    List<Map<String, Object>> mine = jobs().stream().map(Server::M)
                            .filter(j -> S(j, "status").equals("PENDING") && S(j, "clientPhone").equals(from) && I(j, "attempts", 0) < 5).collect(Collectors.toList());
                    if (mine.isEmpty()) return "No job is waiting for your confirmation.";
                    for (var j : mine) if (sha(t[1] + S(j, "id")).equals(S(j, "codeHash"))) { finish(j, rating, rating >= 4, "via SMS", Instant.now().truncatedTo(ChronoUnit.SECONDS).toString()); return "Thank you! Confirmed: " + S(j, "title") + " (" + rating + "/5)."; }
                    for (var j : mine) j.put("attempts", I(j, "attempts", 0) + 1);
                    save(); return "Wrong code. Please check the SMS and try again.";
                }
                case "MY": {
                    if (w == null) return "Not registered. Send: REG <name> <trade> <city>";
                    var s = stats(S(w, "id"));
                    return S(w, "name") + ": " + s.get("verifiedJobs") + " verified jobs, " + s.get("distinctClients") + " clients, score " + s.get("score") + "/100 (" + s.get("level") + "). Profile: " + BASE + "/#/w/" + S(w, "id");
                }
                default: return "SkillProof SMS: REG name trade city | JOB work clientphone | MY | (client) YES code stars";
            }
        } catch (ApiError e) { return e.getMessage(); }
    }

    // ---------- HTTP ----------
    static Map<String, String> query(HttpExchange ex) {
        Map<String, String> q = new HashMap<>(); String raw = ex.getRequestURI().getRawQuery();
        if (raw == null) return q;
        for (String kv : raw.split("&")) { String[] p = kv.split("=", 2); q.put(URLDecoder.decode(p[0], StandardCharsets.UTF_8), p.length > 1 ? URLDecoder.decode(p[1], StandardCharsets.UTF_8) : ""); }
        return q;
    }
    static Map<String, Object> body(HttpExchange ex) throws IOException {
        byte[] raw = ex.getRequestBody().readNBytes(64 * 1024);
        if (raw.length == 0) return new LinkedHashMap<>();
        try { Object o = Json.parse(new String(raw, StandardCharsets.UTF_8)); if (o instanceof Map) return M(o); }
        catch (RuntimeException e) { /* fall through */ }
        throw bad("Request body must be valid JSON");
    }
    static void send(HttpExchange ex, int status, String type, byte[] data) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(status, data.length == 0 ? -1 : data.length);
        if (data.length > 0) try (OutputStream os = ex.getResponseBody()) { os.write(data); }
    }
    static void json(HttpExchange ex, int status, Object o) throws IOException { send(ex, status, "application/json; charset=utf-8", Json.str(o).getBytes(StandardCharsets.UTF_8)); }

    static Object route(String m, String[] p, Map<String, Object> b, Map<String, String> q, HttpExchange ex) {
        String a = p[0];
        if (m.equals("GET") && a.equals("health")) return Map.of("ok", true, "dev", DEV);
        if (m.equals("POST") && a.equals("register")) return register(b);
        if (m.equals("POST") && a.equals("login")) return login(b);
        if (m.equals("GET") && a.equals("me")) {
            Map<String, Object> w = auth(ex); Map<String, Object> r = new LinkedHashMap<>();
            r.put("worker", workerSelf(w)); r.put("stats", stats(S(w, "id")));
            List<Map<String, Object>> mine = jobs().stream().map(Server::M).filter(j -> S(j, "workerId").equals(S(w, "id"))).collect(Collectors.toList());
            Collections.reverse(mine); r.put("jobs", mine.stream().map(Server::ownerJob).collect(Collectors.toList())); return r;
        }
        if (m.equals("POST") && a.equals("jobs") && p.length == 1) {
            Map<String, Object> w = auth(ex);
            Map<String, Object> j = createJob(w, S(b, "title"), S(b, "city"), S(b, "date"), S(b, "clientName"), S(b, "clientPhone"), true);
            Map<String, Object> r = new LinkedHashMap<>(); r.put("job", ownerJob(j)); r.put("verifyLink", BASE + "/#/verify/" + S(j, "id"));
            r.put("message", "SMS with a confirm code was sent to the client. The job counts after they confirm."); return r;
        }
        if (a.equals("jobs") && p.length == 3 && p[2].equals("verify-info") && m.equals("GET")) {
            Map<String, Object> j = jobById(p[1]); if (j == null) throw new ApiError(404, "Job not found");
            Map<String, Object> w = workerById(S(j, "workerId"));
            return Map.of("id", S(j, "id"), "title", S(j, "title"), "city", S(j, "city"), "date", S(j, "date"), "status", S(j, "status"),
                    "worker", S(w, "name"), "trade", S(w, "trade"), "clientHint", mask(S(j, "clientPhone")));
        }
        if (a.equals("jobs") && p.length == 3 && p[2].equals("verify") && m.equals("POST")) {
            Map<String, Object> j = jobById(p[1]); if (j == null) throw new ApiError(404, "Job not found");
            verify(j, S(b, "code"), I(b, "rating", 5), B(b, "again"), S(b, "note"));
            return Map.of("ok", true, "message", "Thank you! Your confirmation is now part of " + S(workerById(S(j, "workerId")), "name") + "'s record.");
        }
        if (a.equals("workers") && m.equals("GET")) {
            if (p.length == 1) {
                String tr = q.getOrDefault("trade", "").toLowerCase(), ci = q.getOrDefault("city", "").toLowerCase(), nm = q.getOrDefault("q", "").toLowerCase();
                return workers().stream().map(Server::M)
                        .filter(w -> S(w, "trade").toLowerCase().contains(tr) && S(w, "city").toLowerCase().contains(ci) && S(w, "name").toLowerCase().contains(nm))
                        .map(Server::workerSummary)
                        .sorted((x, y) -> Integer.compare(I(M(y.get("stats")), "score", 0), I(M(x.get("stats")), "score", 0)))
                        .limit(50).collect(Collectors.toList());
            }
            Map<String, Object> w = workerById(p[1]); if (w == null) throw new ApiError(404, "Worker not found");
            if (p.length == 2) return workerProfile(w);
            if (p.length == 3 && p[2].equals("audit")) return audit(w);
        }
        if (m.equals("POST") && a.equals("sms")) {
            String reply = sms(S(b, "from"), S(b, "text"));
            sendSms(phone(S(b, "from")), reply);   // the reply also lands in the sender's (demo) inbox
            return Map.of("reply", reply);
        }
        if (DEV && m.equals("GET") && a.equals("dev") && p.length == 2 && p[1].equals("outbox")) {
            String ph = q.getOrDefault("phone", "");
            return OUTBOX.stream().filter(x -> ph.isEmpty() || S(x, "to").equals(ph.replaceAll("\\D", ""))).collect(Collectors.toList());
        }
        throw new ApiError(404, "Unknown endpoint");
    }

    static final Map<String, String> MIME = Map.of("html", "text/html; charset=utf-8", "js", "text/javascript; charset=utf-8", "css", "text/css; charset=utf-8",
            "json", "application/json", "png", "image/png", "svg", "image/svg+xml", "ico", "image/x-icon");

    static void handle(HttpExchange ex) {
        try {
            ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");          // so your teammates' frontend on another port can call this API
            ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
            ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            String method = ex.getRequestMethod(), path = ex.getRequestURI().getPath();
            if (method.equals("OPTIONS")) { ex.sendResponseHeaders(204, -1); return; }
            if (path.startsWith("/api/")) {
                String[] p = path.substring(5).split("/");
                Map<String, Object> b = method.equals("POST") ? body(ex) : Map.of();
                Object res;
                synchronized (LOCK) { res = route(method, p, b, query(ex), ex); }
                json(ex, 200, res);
            } else {
                Path f = PUBLIC.resolve(path.equals("/") ? "index.html" : path.substring(1)).normalize();
                if (!f.startsWith(PUBLIC) || !Files.isRegularFile(f)) { send(ex, 404, "text/plain", "Not found".getBytes()); return; }
                String name = f.getFileName().toString(); String ext = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1) : "";
                send(ex, 200, MIME.getOrDefault(ext, "application/octet-stream"), Files.readAllBytes(f));
            }
        } catch (ApiError e) {
            try { json(ex, e.status, Map.of("error", e.getMessage())); } catch (IOException ignored) { }
        } catch (Exception e) {
            e.printStackTrace();
            try { json(ex, 500, Map.of("error", "Server error")); } catch (IOException ignored) { }
        } finally { ex.close(); }
    }

    // ---------- demo data ----------
    static int seedN = 0;
    static void seedJob(Map<String, Object> w, String title, int daysAgo, String client, int rating, boolean again, int clientNo) {
        String cp = "90000" + String.format("%05d", clientNo);
        Map<String, Object> j = createJob(w, title, "", LocalDate.now().minusDays(daysAgo).toString(), client, cp, false);
        finish(j, rating, again, "", LocalDate.now().minusDays(daysAgo).toString() + "T10:00:00Z");
    }
    static void seed() {
        var r = newWorker("Ramesh Kumar", "9876500001", "painter", "Pune", 22, "1234");
        String[][] rj = { {"2BHK full repaint", "700", "Anita Sharma", "5", "1", "1"}, {"Texture wall, living room", "640", "Anita Sharma", "5", "1", "1"},
                {"Shop front painting", "560", "Imran Shaikh", "4", "1", "2"}, {"Waterproofing + paint, terrace", "480", "Dr. Joshi", "5", "1", "3"},
                {"Office repaint (3 rooms)", "400", "Vikas Patil", "4", "1", "4"}, {"Bedroom wall + ceiling", "330", "Neha Kulkarni", "5", "1", "5"},
                {"Gate & grill enamel", "300", "Suresh Rao", "4", "0", "6"}, {"1BHK touch-up before rent", "240", "Pooja Mehta", "5", "1", "7"},
                {"Villa exterior", "190", "Kiran Desai", "5", "1", "8"}, {"Kitchen cabinets polish", "120", "Anita Sharma", "5", "1", "1"},
                {"Staircase repaint", "80", "Farhan Q", "4", "1", "9"}, {"Flat repaint 2BHK", "30", "Meera Iyer", "5", "1", "10"} };
        for (String[] x : rj) seedJob(r, x[0], Integer.parseInt(x[1]), x[2], Integer.parseInt(x[3]), x[4].equals("1"), 100 + Integer.parseInt(x[5]));
        var s = newWorker("Salim Ansari", "9876500002", "electrician", "Bengaluru", 15, "1234");
        seedJob(s, "Full house rewiring", 300, "Rohit Nair", 5, true, 201); seedJob(s, "MCB panel upgrade", 210, "Divya R", 4, true, 202);
        seedJob(s, "Fan + light fittings", 120, "Rohit Nair", 5, true, 201); seedJob(s, "Inverter wiring", 60, "Karthik S", 4, false, 203);
        var m = newWorker("Meena Devi", "9876500003", "tailor", "Jaipur", 18, "1234");
        seedJob(m, "Bridal lehenga stitching", 150, "Sunita Agarwal", 5, true, 301); seedJob(m, "School uniforms x6", 70, "Rakesh Jain", 4, true, 302);
        newWorker("Gopal Yadav", "9876500004", "carpenter", "Lucknow", 20, "1234");   // new worker: claims 20 years, nothing proven yet
        save();
        System.out.println("Demo data created. Login with phone 9876500001 / PIN 1234 (Ramesh), ...02 Salim, ...03 Meena, ...04 Gopal (empty record).");
    }

    public static void main(String[] args) throws Exception {
        load();
        if (workers().isEmpty()) seed();
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/", Server::handle);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        System.out.println("SkillProof running at " + BASE + "   (DEV=" + DEV + ")");
    }
}
