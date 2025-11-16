/* GuessingGameWebServer.java
   Improved UI version with aesthetic background and images.
   - Same functionality as before (register/login/game/leaderboard)
   - PBKDF2 password hashing, CSV storage
   - Single-file Java 17+ using com.sun.net.httpserver
   - Enhanced CSS: background images, glass cards, animations
*/

import com.sun.net.httpserver.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class GuessingGameWebServer {

    // ---------------- CONFIG ----------------
    private static final Path USERS_FILE = Paths.get("users.csv");
    private static final Path SCORES_FILE = Paths.get("scores.csv");
    private static final int DEFAULT_PORT = 8080;

    private static final ExecutorService executor = Executors.newFixedThreadPool(12);
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Random rnd = new Random();

    // session store
    private static final Map<String, String> sessions = new ConcurrentHashMap<>();
    private static final Map<String, GameState> gameStates = new ConcurrentHashMap<>();

    // PBKDF2 config
    private static final String PBKDF2_ALGO = "PBKDF2WithHmacSHA256";
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    private static final int PBKDF2_ITER = 65000;

    public static void main(String[] args) throws Exception {
        ensureFiles();
        int port = parsePort(args);
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/", new IndexHandler());
        server.createContext("/login", new LoginHandler());
        server.createContext("/register", new RegisterHandler());
        server.createContext("/logout", new LogoutHandler());
        server.createContext("/game", new GameHandler());
        server.createContext("/start", new StartHandler());
        server.createContext("/guess", new GuessHandler());
        server.createContext("/leaderboard", new LeaderboardHandler());
        server.createContext("/static/", new StaticHandler());

        server.setExecutor(executor);
        System.out.println("🔥 Server started at: http://localhost:" + port);
        server.start();
    }

    // ---------------- INITIAL SETUP ----------------

    private static void ensureFiles() throws IOException {
        if (!Files.exists(USERS_FILE)) {
            Files.writeString(USERS_FILE, "username,salt,hash\n");
        }
        if (!Files.exists(SCORES_FILE)) {
            Files.writeString(SCORES_FILE, "username,attempts,level,timestamp\n");
        }
    }

    private static int parsePort(String[] args) {
        if (args.length == 0) return DEFAULT_PORT;
        try { return Integer.parseInt(args[0]); } catch (Exception e) { return DEFAULT_PORT; }
    }

    // ---------------- PASSWORD HASHING ----------------

    private static byte[] pbkdf2(char[] pass, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(pass, salt, PBKDF2_ITER, HASH_BYTES * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGO);
        return skf.generateSecret(spec).getEncoded();
    }

    private static boolean verifyPassword(String password, String saltB64, String hashB64) {
        try {
            byte[] salt = Base64.getDecoder().decode(saltB64);
            byte[] expected = Base64.getDecoder().decode(hashB64);
            byte[] actual = pbkdf2(password.toCharArray(), salt);
            return Arrays.equals(expected, actual);
        } catch (Exception e) {
            return false;
        }
    }

    // ---------------- USER STORAGE ----------------

    private static synchronized boolean saveUser(String username, String password) throws Exception {
        Map<String, UserRecord> users = loadUsers();
        if (users.containsKey(username)) return false;

        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);

        byte[] hash = pbkdf2(password.toCharArray(), salt);

        String line = username + "," +
                Base64.getEncoder().encodeToString(salt) + "," +
                Base64.getEncoder().encodeToString(hash) + "\n";

        Files.writeString(USERS_FILE, line, StandardOpenOption.APPEND);
        return true;
    }

    private static synchronized Map<String, UserRecord> loadUsers() throws IOException {
        Map<String, UserRecord> map = new HashMap<>();
        List<String> lines = Files.readAllLines(USERS_FILE);
        for (int i = 1; i < lines.size(); i++) {
            String ln = lines.get(i).trim();
            if (ln.isEmpty()) continue;
            String[] p = ln.split(",", -1);
            if (p.length >= 3) {
                map.put(p[0], new UserRecord(p[0], p[1], p[2]));
            }
        }
        return map;
    }

    // ---------------- SCORE STORAGE ----------------

    private static synchronized void saveScore(String username, int attempts, String level) throws IOException {
        String line = username + "," + attempts + "," + level + "," + Instant.now().getEpochSecond() + "\n";
        Files.writeString(SCORES_FILE, line, StandardOpenOption.APPEND);
    }

    private static synchronized List<Score> loadScores() throws IOException {
        List<Score> out = new ArrayList<>();
        List<String> lines = Files.readAllLines(SCORES_FILE);
        for (int i = 1; i < lines.size(); i++) {
            String ln = lines.get(i).trim();
            if (ln.isEmpty()) continue;
            String[] p = ln.split(",", -1);
            if (p.length >= 4) {
                out.add(new Score(p[0], Integer.parseInt(p[1]), p[2], Long.parseLong(p[3])));
            }
        }
        return out;
    }

    // ---------------- HTTP HELPERS ----------------

    private static String getCookie(HttpExchange ex, String name) {
        List<String> cookies = ex.getRequestHeaders().get("Cookie");
        if (cookies == null) return null;
        for (String s : cookies) {
            for (String c : s.split(";")) {
                String[] p = c.trim().split("=", 2);
                if (p.length == 2 && p[0].equals(name)) return p[1];
            }
        }
        return null;
    }

    private static void setCookie(HttpExchange ex, String name, String val) {
        ex.getResponseHeaders().add("Set-Cookie", name + "=" + val + "; Path=/; HttpOnly");
    }

    private static void deleteCookie(HttpExchange ex, String name) {
        ex.getResponseHeaders().add("Set-Cookie", name + "=x; Max-Age=0; Path=/");
    }

    // ---------------- FIXED FORM PARSER ----------------

    private static Map<String, String> parseForm(InputStream stream, int length) throws IOException {
        byte[] data;
        if (length > 0) data = stream.readNBytes(length);
        else data = stream.readAllBytes();

        String body = new String(data, StandardCharsets.UTF_8).trim();
        if (body.isEmpty()) return Collections.emptyMap();

        return Arrays.stream(body.split("&"))
                .map(s -> s.split("=", 2))
                .filter(p -> p.length == 2)
                .collect(Collectors.toMap(
                        p -> urlDecode(p[0]),
                        p -> urlDecode(p[1]),
                        (oldV, newV) -> newV
                ));
    }

    private static String urlDecode(String s) {
        try { return URLDecoder.decode(s, StandardCharsets.UTF_8); } catch (Exception e) { return s; }
    }

    private static void redirect(HttpExchange ex, String loc) throws IOException {
        ex.getResponseHeaders().add("Location", loc);
        ex.sendResponseHeaders(302, -1);
        ex.close();
    }

    private static void sendHtml(HttpExchange ex, String html) throws IOException {
        byte[] out = html.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(200, out.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(out);
        }
    }

    // ---------------- HANDLERS ----------------

    static class IndexHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String u = getSessionUser(ex);
            String action = (u == null)
                    ? "<a class='btn btn-cta' href='/register'>Get Started</a>"
                    : "<a class='btn btn-cta' href='/game'>Play Now</a>";

            String hero = """
                <div class="hero">
                  <div class="hero-inner">
                    <h1 class="display">Guessing Game</h1>
                    <p class="subtitle">Pick a difficulty, guess the number — beat the leaderboard.</p>
                    <div class="hero-actions">""" + action + " <a class='btn btn-outline' href='/leaderboard'>Leaderboard</a></div>" +
                "</div></div>";

            sendHtml(ex, layout("Welcome", u, hero));
        }
    }

    static class RegisterHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (ex.getRequestMethod().equals("GET")) {
                sendHtml(ex, layout("Register", null, registerForm("")));
                return;
            }

            int len = getLength(ex);
            Map<String, String> form = parseForm(ex.getRequestBody(), len);

            String username = form.getOrDefault("username", "").trim();
            String password = form.getOrDefault("password", "").trim();

            if (username.isEmpty() || password.isEmpty()) {
                sendHtml(ex, layout("Register", null, registerForm("<div class='alert alert-danger'>All fields required.</div>")));
                return;
            }

            try {
                if (!saveUser(username, password)) {
                    sendHtml(ex, layout("Register", null, registerForm("<div class='alert alert-danger'>User already exists.</div>")));
                } else {
                    sendHtml(ex, layout("Register", null,
                            "<div class='alert alert-success'>Account created. <a href='/login'>Login here</a>.</div>"));
                }
            } catch (Exception e) {
                sendHtml(ex, layout("Register", null, "<div class='alert alert-danger'>Server error.</div>"));
            }
        }
    }

    static class LoginHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (ex.getRequestMethod().equals("GET")) {
                sendHtml(ex, layout("Login", null, loginForm("")));
                return;
            }

            int len = getLength(ex);
            Map<String, String> form = parseForm(ex.getRequestBody(), len);

            String username = form.getOrDefault("username", "");
            String password = form.getOrDefault("password", "");

            try {
                Map<String, UserRecord> users = loadUsers();
                UserRecord ur = users.get(username);

                if (ur != null && verifyPassword(password, ur.saltB64, ur.hashB64)) {
                    String sid = UUID.randomUUID().toString();
                    sessions.put(sid, username);
                    setCookie(ex, "SESSIONID", sid);
                    redirect(ex, "/game");
                } else {
                    sendHtml(ex, layout("Login", null, loginForm("<div class='alert alert-danger'>Invalid credentials</div>")));
                }
            } catch (Exception e) {
                sendHtml(ex, layout("Login", null, loginForm("<div class='alert alert-danger'>Server error</div>")));
            }
        }
    }

    static class LogoutHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String sid = getCookie(ex, "SESSIONID");
            if (sid != null) sessions.remove(sid);
            deleteCookie(ex, "SESSIONID");
            redirect(ex, "/");
        }
    }

    static class GameHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String user = getSessionUser(ex);
            if (user == null) { redirect(ex, "/login"); return; }

            String sid = getCookie(ex, "SESSIONID");
            GameState state = gameStates.get(sid);
            String msg = getParam(ex, "msg");
            String body = (state == null || !state.active) ? gameMenu(msg) : gamePlay(msg, state);

            sendHtml(ex, layout("Play", user, body));
        }
    }

    static class StartHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String user = getSessionUser(ex);
            if (user == null) { redirect(ex, "/login"); return; }

            int len = getLength(ex);
            Map<String, String> form = parseForm(ex.getRequestBody(), len);

            String level = form.getOrDefault("level", "MEDIUM").toUpperCase();
            int target = genTarget(level);
            int attempts = attemptsFor(level);

            String sid = getCookie(ex, "SESSIONID");
            gameStates.put(sid, new GameState(level, target, attempts));

            redirect(ex, "/game");
        }
    }

    static class GuessHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String user = getSessionUser(ex);
            if (user == null) { redirect(ex, "/login"); return; }

            String sid = getCookie(ex, "SESSIONID");
            GameState st = gameStates.get(sid);

            if (st == null || !st.active) { redirect(ex, "/game?msg=Start+a+new+game+first"); return; }

            int len = getLength(ex);
            Map<String, String> form = parseForm(ex.getRequestBody(), len);
            int guess = Integer.parseInt(form.getOrDefault("guess", "0"));

            st.attemptsLeft--;
            st.attemptsUsed++;

            if (guess == st.target) {
                try { saveScore(user, st.attemptsUsed, st.level); } catch (Exception ignored) {}
                st.active = false;
                redirect(ex, "/game?msg=Correct!+You+won+in+" + st.attemptsUsed + "+attempts");
            } else if (st.attemptsLeft <= 0) {
                st.active = false;
                redirect(ex, "/game?msg=Out+of+attempts!+Correct+number+was+" + st.target);
            } else if (guess < st.target) {
                redirect(ex, "/game?msg=Too+Low!+" + st.attemptsLeft + "+left");
            } else {
                redirect(ex, "/game?msg=Too+High!+" + st.attemptsLeft + "+left");
            }
        }
    }

    static class LeaderboardHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String user = getSessionUser(ex);
            List<Score> scores = loadScores();
            scores.sort(Comparator.comparingInt(a -> a.attempts));

            StringBuilder sb = new StringBuilder();
            sb.append("<div class='card p-4 shadow-sm'><h3>Leaderboard</h3><ol>");
            for (Score s : scores.stream().limit(20).toList()) {
                sb.append("<li>").append(escapeHtml(s.username)).append(" — ").append(s.attempts)
                        .append(" attempts (").append(escapeHtml(s.level)).append(")</li>");
            }
            sb.append("</ol></div>");

            sendHtml(ex, layout("Leaderboard", user, sb.toString()));
        }
    }

    static class StaticHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String file = ex.getRequestURI().getPath().replace("/static/", "");
            if (!file.equals("style.css")) { ex.sendResponseHeaders(404, -1); return; }
            byte[] css = STYLE.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "text/css; charset=utf-8");
            ex.sendResponseHeaders(200, css.length);
            ex.getResponseBody().write(css);
            ex.close();
        }
    }

    // ---------------- UI HTML ----------------

    private static String layout(String title, String user, String body) {
        return """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>%s - Guessing Game</title>
          <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet">
          <link href="/static/style.css" rel="stylesheet">
        </head>
        <body>
          <div class="bg-overlay"></div>
          <nav class="navbar navbar-expand-lg navbar-dark topbar">
            <div class="container">
              <a class="navbar-brand d-flex align-items-center gap-2" href="/">
                %s
                <span class="brand-text">GuessingGame</span>
              </a>
              <div class="ms-auto nav-items">%s</div>
            </div>
          </nav>

          <main class="container py-5">
            %s
          </main>

        </body>
        </html>
        """.formatted(escapeHtml(title), logoSvg(), navHtml(user), body);
    }

    private static String logoSvg() {
        // small neat SVG icon
        return "<svg width='34' height='34' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg' aria-hidden='true'>"
                + "<rect width='24' height='24' rx='6' fill='white' opacity='0.08'/>"
                + "<path d='M6 12h12' stroke='white' stroke-width='1.6' stroke-linecap='round'/>"
                + "<circle cx='8' cy='8' r='1.8' fill='white'/>"
                + "<circle cx='16' cy='16' r='1.8' fill='white'/>"
                + "</svg>";
    }

    private static String navHtml(String u) {
        if (u == null) {
            return "<a class='nav-link' href='/leaderboard'>Leaderboard</a>"
                    + "<a class='nav-link' href='/login'>Login</a>"
                    + "<a class='btn btn-cta ms-2' href='/register'>Register</a>";
        } else {
            return "<a class='nav-link' href='/leaderboard'>Leaderboard</a>"
                    + "<span class='nav-link'>Hi, " + escapeHtml(u) + "</span>"
                    + "<a class='btn btn-cta ms-2' href='/game'>Play</a>"
                    + "<a class='nav-link ms-2' href='/logout'>Logout</a>";
        }
    }

    private static String registerForm(String errHtml) {
        return """
        <div class='row justify-content-center'>
          <div class='col-md-6'>
            <div class='glass card p-4'>
              <h3 class='mb-3'>Create account</h3>
              %s
              <form method='post'>
                <input name='username' class='form-control mb-3' placeholder='Username' required>
                <input name='password' class='form-control mb-3' placeholder='Password' type='password' required>
                <div class='d-flex gap-2'><button class='btn btn-cta'>Register</button><a class='btn btn-outline' href='/login'>Login</a></div>
              </form>
            </div>
          </div>
        </div>
        """.formatted(errHtml == null ? "" : errHtml);
    }

    private static String loginForm(String errHtml) {
        return """
        <div class='row justify-content-center'>
          <div class='col-md-6'>
            <div class='glass card p-4'>
              <h3 class='mb-3'>Welcome back</h3>
              %s
              <form method='post'>
                <input name='username' class='form-control mb-3' placeholder='Username' required>
                <input name='password' class='form-control mb-3' placeholder='Password' type='password' required>
                <div class='d-flex gap-2'><button class='btn btn-cta'>Login</button><a class='btn btn-outline' href='/register'>Register</a></div>
              </form>
            </div>
          </div>
        </div>
        """.formatted(errHtml == null ? "" : errHtml);
    }

    private static String gameMenu(String msg) {
        return """
        <div class='row'>
          <div class='col-md-8'>
            <div class='glass card p-4'>
              <h3>Start a new game</h3>
              %s
              <form method='post' action='/start'>
                <select name='level' class='form-select mb-3'><option value='EASY'>Easy (1-50)</option><option value='MEDIUM' selected>Medium (1-100)</option><option value='HARD'>Hard (1-200)</option></select>
                <button class='btn btn-cta'>Start Game</button>
              </form>
            </div>
          </div>
          <div class='col-md-4'>
            <div class='glass card p-3'>
              <h5>Top scores</h5>
              %s
            </div>
          </div>
        </div>
        """.formatted(msg == null ? "" : "<div class='alert alert-info mb-3'>"+escapeHtml(msg)+"</div>", topScoresHtml());
    }

    private static String gamePlay(String msg, GameState st) {
        return """
        <div class='row'>
          <div class='col-md-8'>
            <div class='glass card p-4'>
              <h3>Guess the number — <small>%s</small></h3>
              %s
              <form method='post' action='/guess'>
                <input name='guess' type='number' class='form-control mb-3' placeholder='Enter your guess' required>
                <button class='btn btn-cta'>Submit Guess</button>
              </form>
              <p class='mt-3 text-muted'>Attempts left: <strong>%d</strong></p>
            </div>
          </div>
          <div class='col-md-4'>
            <div class='glass card p-3'>
              <h5>Top scores</h5>
              %s
            </div>
          </div>
        </div>
        """.formatted(escapeHtml(st.level), (msg==null?"":"<div class='alert alert-info mb-3'>"+escapeHtml(msg)+"</div>"), st.attemptsLeft, topScoresHtml());
    }

    private static String topScoresHtml() {
        try {
            List<Score> top = loadScores().stream().sorted(Comparator.comparingInt(s -> s.attempts)).limit(8).collect(Collectors.toList());
            StringBuilder sb = new StringBuilder("<ol class='score-list'>");
            for (Score s : top) sb.append("<li>").append(escapeHtml(s.username)).append(" — ").append(s.attempts).append(" (").append(escapeHtml(s.level)).append(")</li>");
            sb.append("</ol>");
            return sb.toString();
        } catch (Exception e) {
            return "<div class='text-muted'>No scores yet.</div>";
        }
    }

    // ---------------- GETTERS ----------------

    private static String getParam(HttpExchange ex, String key) {
        String q = ex.getRequestURI().getQuery();
        if (q == null) return null;
        for (String p : q.split("&")) {
            String[] kv = p.split("=", 2);
            if (kv.length == 2 && kv[0].equals(key)) return urlDecode(kv[1]);
        }
        return null;
    }

    private static int getLength(HttpExchange ex) {
        try { return Integer.parseInt(ex.getRequestHeaders().getFirst("Content-length")); } catch (Exception e) { return -1; }
    }

    private static String getSessionUser(HttpExchange ex) {
        String sid = getCookie(ex, "SESSIONID");
        if (sid == null) return null;
        return sessions.get(sid);
    }

    // ---------------- GAME HELPERS ----------------

    private static int genTarget(String level) {
        return switch (level) {
            case "EASY" -> rnd.nextInt(50) + 1;
            case "MEDIUM" -> rnd.nextInt(100) + 1;
            default -> rnd.nextInt(200) + 1;
        };
    }

    private static int attemptsFor(String level) {
        return switch (level) {
            case "EASY" -> 10;
            case "MEDIUM" -> 7;
            default -> 5;
        };
    }

    // ---------------- DATA CLASSES ----------------

    static class GameState {
        String level;
        int target;
        int attemptsLeft;
        int attemptsUsed = 0;
        boolean active = true;
        GameState(String l, int t, int a) { level = l; target = t; attemptsLeft = a; }
    }

    static class Score {
        String username; int attempts; String level; long ts;
        Score(String u, int a, String l, long t) { username=u; attempts=a; level=l; ts=t; }
    }

    static class UserRecord {
        String username; String saltB64; String hashB64;
        UserRecord(String u, String s, String h) { username=u; saltB64=s; hashB64=h; }
    }

    // ---------------- CSS (aesthetic) ----------------
    // background images from Unsplash (CDN). If offline, gradient will still show.
    private static final String STYLE = """
    :root{
      --accent:#3461ff;
      --accent-2:#6b8bff;
      --glass-bg: rgba(255,255,255,0.08);
      --glass-border: rgba(255,255,255,0.12);
      --muted: rgba(255,255,255,0.8);
    }
    html,body{height:100%;margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,'Helvetica Neue',Arial;}
    body{
      color: #fff;
      background: linear-gradient(180deg, rgba(10,10,25,0.55), rgba(10,10,25,0.75)),
        url('https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?q=80&w=1600&auto=format&fit=crop&ixlib=rb-4.0.3&s=9a6de4d2b5b8aef6c6a1a4f3b0a7b2a9') center/cover no-repeat fixed;
      background-blend-mode: overlay;
      -webkit-font-smoothing:antialiased;
      -moz-osx-font-smoothing:grayscale;
    }
    .bg-overlay{
      position:fixed;inset:0;
      background: linear-gradient(135deg, rgba(5,10,40,0.35), rgba(30,10,60,0.45));
      pointer-events:none;mix-blend-mode:multiply;
    }
    .topbar{backdrop-filter: blur(6px); background: linear-gradient(90deg, rgba(32,58,255,0.9), rgba(60,40,180,0.9)); box-shadow:0 6px 18px rgba(2,6,23,0.5);}
    .navbar-brand{display:flex;align-items:center;gap:10px;color:#fff;font-weight:700}
    .brand-text{font-size:20px}
    .nav-items a, .nav-items span{color:rgba(255,255,255,0.9); margin-left:14px; text-decoration:none}
    .btn-cta{background:linear-gradient(90deg,var(--accent),var(--accent-2));border:none;color:white;padding:10px 16px;border-radius:10px;box-shadow:0 8px 24px rgba(52,97,255,0.25);transition:transform .18s ease, box-shadow .18s ease}
    .btn-cta:hover{transform:translateY(-3px);box-shadow:0 18px 40px rgba(52,97,255,0.32)}
    .btn-outline{background:transparent;border:1px solid rgba(255,255,255,0.12);color:white;padding:8px 12px;border-radius:10px}
    main.container{min-height:calc(100vh - 80px)}
    .hero{display:flex;align-items:center;justify-content:center;padding:100px 0 60px}
    .hero-inner{max-width:900px;text-align:center}
    .display{font-size:48px;margin-bottom:8px;letter-spacing:0.6px}
    .subtitle{color:rgba(255,255,255,0.9);margin-bottom:20px}
    .hero-actions{display:flex;gap:12px;justify-content:center;margin-top:18px}

    /* glass effect cards */
    .glass{background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:14px;box-shadow:0 8px 30px rgba(2,6,23,0.45);backdrop-filter: blur(8px);color:#fff}
    input.form-control{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.08);color:#fff}
    input::placeholder{color:rgba(255,255,255,0.7)}
    .card h3,.card h5{color:#fff}
    .score-list{padding-left:18px;color:rgba(255,255,255,0.95)}
    .alert{border-radius:10px}

    /* responsive tweaks */
    @media (max-width:767px){
      .display{font-size:32px;padding:30px 12px}
      .hero{padding:40px 0}
      .nav-items{display:flex;flex-direction:column;gap:8px}
    }
    """;

    // ---------------- UTILITIES ----------------

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;");
    }

    // ---------------- OPTIONAL SMALL HELPERS (unused stubs kept safe) ----------------
    // (previous file had some extra unused methods; kept nothing harmful)

    // ---------------- END ----------------
}
