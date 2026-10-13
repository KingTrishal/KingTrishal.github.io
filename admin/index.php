<?php
declare(strict_types=1);

/* ---------- Slide manager for the Kingtrishal site ----------
   Visit  /admin/  -> first time: choose a password. After that: log in,
   upload images, reorder, delete. The homepage reads slides.json. */

session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'secure' => !empty($_SERVER['HTTPS'])]);
session_start();

const ROOT_DIR   = __DIR__ . '/..';
const CONFIG_F   = __DIR__ . '/config.php';
const SLIDES_F   = ROOT_DIR . '/slides.json';
const UPLOAD_DIR = ROOT_DIR . '/uploads';
const MAX_BYTES  = 15 * 1024 * 1024;
const MAX_SIDE   = 2200;   // larger uploads are scaled down (needs PHP GD)

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

function load_slides(): array {
    $raw = @file_get_contents(SLIDES_F);
    $d = $raw ? json_decode($raw, true) : null;
    $list = is_array($d['slides'] ?? null) ? $d['slides'] : [];
    return array_values(array_filter($list, 'is_string'));
}
function save_slides(array $list): bool {
    $json = json_encode(['slides' => array_values($list)], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    return file_put_contents(SLIDES_F, $json, LOCK_EX) !== false;
}
function flash(string $m, bool $ok = true): void { $_SESSION['flash'] = [$m, $ok]; }
function go(): never { header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?')); exit; }

if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
$csrf = $_SESSION['csrf'];
$setup = !file_exists(CONFIG_F);
$config = $setup ? [] : (include CONFIG_F);
$authed = !$setup && !empty($_SESSION['ok']);

/* ---------- image handling ---------- */
function store_image(array $f, string &$err): ?string {
    if ($f['error'] !== UPLOAD_ERR_OK) { $err = 'upload error ' . $f['error'] . ' (file too big for the server?)'; return null; }
    if ($f['size'] > MAX_BYTES)        { $err = 'larger than 15 MB'; return null; }
    $info = @getimagesize($f['tmp_name']);
    $types = [IMAGETYPE_JPEG => 'jpg', IMAGETYPE_PNG => 'png', IMAGETYPE_GIF => 'gif', IMAGETYPE_WEBP => 'webp'];
    if (!$info || !isset($types[$info[2]])) { $err = 'not a JPG, PNG, GIF or WEBP image'; return null; }
    $ext  = $types[$info[2]];
    $name = 'slide_' . date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
    $dest = UPLOAD_DIR . '/' . $name;
    if (!is_dir(UPLOAD_DIR)) @mkdir(UPLOAD_DIR, 0755, true);

    $done = false;
    if (max($info[0], $info[1]) > MAX_SIDE && $info[2] !== IMAGETYPE_GIF && function_exists('imagecreatetruecolor')) {
        $src = match ($info[2]) {
            IMAGETYPE_JPEG => @imagecreatefromjpeg($f['tmp_name']),
            IMAGETYPE_PNG  => @imagecreatefrompng($f['tmp_name']),
            IMAGETYPE_WEBP => function_exists('imagecreatefromwebp') ? @imagecreatefromwebp($f['tmp_name']) : false,
        };
        if ($src) {
            if ($info[2] === IMAGETYPE_JPEG && function_exists('exif_read_data')) {
                $ex = @exif_read_data($f['tmp_name']);
                $rot = [3 => 180, 6 => -90, 8 => 90][$ex['Orientation'] ?? 1] ?? 0;
                if ($rot) $src = imagerotate($src, $rot, 0) ?: $src;
            }
            $w = imagesx($src); $hh = imagesy($src); $k = MAX_SIDE / max($w, $hh);
            $nw = (int)round($w * $k); $nh = (int)round($hh * $k);
            $dst = imagecreatetruecolor($nw, $nh);
            imagealphablending($dst, false); imagesavealpha($dst, true);
            imagecopyresampled($dst, $src, 0, 0, 0, 0, $nw, $nh, $w, $hh);
            $done = match ($info[2]) {
                IMAGETYPE_JPEG => imagejpeg($dst, $dest, 90),
                IMAGETYPE_PNG  => imagepng($dst, $dest, 6),
                IMAGETYPE_WEBP => imagewebp($dst, $dest, 90),
            };
        }
    }
    if (!$done && !move_uploaded_file($f['tmp_name'], $dest)) { $err = 'could not save (is the uploads folder writable?)'; return null; }
    @chmod($dest, 0644);
    return 'uploads/' . $name;
}

/* ---------- actions ---------- */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['action'] ?? '';
    if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) { flash('Session expired, please try again.', false); go(); }

    if ($setup && $act === 'setup') {
        $p = (string)($_POST['pw'] ?? '');
        if (strlen($p) < 8)                      flash('Password must be at least 8 characters.', false);
        elseif ($p !== (string)($_POST['pw2'] ?? '')) flash('Passwords do not match.', false);
        elseif (file_put_contents(CONFIG_F, '<?php return ' . var_export(['hash' => password_hash($p, PASSWORD_DEFAULT)], true) . ';', LOCK_EX) === false)
                                                  flash('Could not write admin/config.php (folder not writable).', false);
        else { session_regenerate_id(true); $_SESSION['ok'] = true; flash('Password set. You are logged in.'); }
        go();
    }
    if (!$setup && $act === 'login') {
        if (($_SESSION['fails'] ?? 0) >= 5 && time() - ($_SESSION['fail_t'] ?? 0) < 60) { flash('Too many attempts. Wait a minute.', false); go(); }
        if (password_verify((string)($_POST['pw'] ?? ''), $config['hash'] ?? '')) {
            session_regenerate_id(true); $_SESSION['ok'] = true; $_SESSION['fails'] = 0;
        } else { $_SESSION['fails'] = ($_SESSION['fails'] ?? 0) + 1; $_SESSION['fail_t'] = time(); sleep(1); flash('Wrong password.', false); }
        go();
    }
    if (!$authed) go();

    $slides = load_slides();
    if ($act === 'logout') { $_SESSION = []; session_destroy(); go(); }

    if ($act === 'upload' && isset($_FILES['images'])) {
        $f = $_FILES['images']; $added = 0; $problems = [];
        foreach ((array)$f['name'] as $i => $n) {
            if ($f['error'][$i] === UPLOAD_ERR_NO_FILE) continue;
            $one = ['name' => $n, 'tmp_name' => $f['tmp_name'][$i], 'size' => $f['size'][$i], 'error' => $f['error'][$i]];
            $err = '';
            if ($p = store_image($one, $err)) { $slides[] = $p; $added++; } else $problems[] = $n . ': ' . $err;
        }
        if ($added && !save_slides($slides)) { flash('Images uploaded but slides.json is not writable.', false); go(); }
        $msg = $added ? "$added slide(s) added." : '';
        if ($problems) $msg .= ' Skipped - ' . implode('; ', $problems);
        flash(trim($msg) ?: 'No file chosen.', $added > 0 && !$problems);
        go();
    }
    $i = (int)($_POST['i'] ?? -1);
    if (isset($slides[$i])) {
        if ($act === 'delete') {
            $p = $slides[$i]; array_splice($slides, $i, 1);
            if (save_slides($slides)) {
                if (str_starts_with($p, 'uploads/') && !str_contains($p, '..')) @unlink(ROOT_DIR . '/' . $p);
                flash('Slide removed.');
            } else flash('slides.json is not writable.', false);
        } elseif ($act === 'up' || $act === 'down') {
            $j = $act === 'up' ? $i - 1 : $i + 1;
            if (isset($slides[$j])) { [$slides[$i], $slides[$j]] = [$slides[$j], $slides[$i]]; save_slides($slides); }
        }
    }
    go();
}

$flash = $_SESSION['flash'] ?? null; unset($_SESSION['flash']);
$slides = $authed ? load_slides() : [];
?><!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Slides admin</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#242426;color:#fff;font:16px/1.5 Arial,Helvetica,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:30px 20px 80px}
h1{font-size:28px;margin:0 0 6px}p.sub{color:#aaa;margin:0 0 24px}
a{color:#0095ff}
.box{background:#2e2e31;border-radius:8px;padding:20px;margin-bottom:24px}
input[type=password],input[type=file]{width:100%;padding:10px;background:#1b1b1d;color:#fff;border:1px solid #444;border-radius:6px;margin:6px 0 14px}
button{background:#0095ff;color:#fff;border:0;border-radius:6px;padding:10px 18px;font-weight:700;cursor:pointer}
button:hover{background:#199dfc}button.sec{background:#444}button.del{background:#c0392b}
button:disabled{opacity:.35;cursor:default}
.msg{padding:12px 16px;border-radius:6px;margin-bottom:20px}.ok{background:#1e5e34}.bad{background:#7a2a22}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:16px}
.card{background:#1b1b1d;border-radius:8px;overflow:hidden;display:flex;flex-direction:column}
.card .im{aspect-ratio:1;background:#000 center/contain no-repeat}
.card .bar{display:flex;gap:6px;align-items:center;padding:8px}.card .bar span{flex:1;color:#aaa;font-size:14px}
.card form{margin:0}.card button{padding:6px 10px}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap}
small{color:#aaa}
</style></head><body><div class="wrap">
<?php if ($flash): ?><div class="msg <?= $flash[1] ? 'ok' : 'bad' ?>"><?= h($flash[0]) ?></div><?php endif; ?>

<?php if ($setup): ?>
  <h1>Set up admin</h1><p class="sub">Choose a password for managing the slideshow. Do this right after uploading the site.</p>
  <form class="box" method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="setup">
    <label>Password (8+ characters)<input type="password" name="pw" required minlength="8" autocomplete="new-password"></label>
    <label>Repeat password<input type="password" name="pw2" required minlength="8" autocomplete="new-password"></label>
    <button>Save password</button></form>

<?php elseif (!$authed): ?>
  <h1>Slides admin</h1><p class="sub">Log in to manage the homepage slideshow.</p>
  <form class="box" method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="login">
    <label>Password<input type="password" name="pw" required autofocus autocomplete="current-password"></label>
    <button>Log in</button></form>

<?php else: ?>
  <div class="top"><div><h1>Slides admin</h1><p class="sub">Slides appear on the homepage in this order.</p></div>
    <div><a href="../" target="_blank">View site &#8599;</a>
    <form method="post" style="display:inline;margin-left:14px"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="logout"><button class="sec">Log out</button></form></div></div>

  <form class="box" method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="upload">
    <label><strong>Add slides</strong> <small>(JPG, PNG, GIF or WEBP, up to 15 MB each - you can pick several)</small>
    <input type="file" name="images[]" accept="image/jpeg,image/png,image/gif,image/webp" multiple required></label>
    <button>Upload</button></form>

  <?php if (!$slides): ?><p>No slides yet.</p><?php endif; ?>
  <div class="grid">
  <?php foreach ($slides as $i => $s): ?>
    <div class="card"><div class="im" style="background-image:url('../<?= h($s) ?>')"></div>
      <div class="bar"><span>#<?= $i + 1 ?></span>
        <?php foreach ([['up', '&larr;', $i === 0], ['down', '&rarr;', $i === count($slides) - 1]] as [$a, $sym, $dis]): ?>
        <form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="<?= $a ?>"><input type="hidden" name="i" value="<?= $i ?>"><button class="sec" <?= $dis ? 'disabled' : '' ?> title="Move"><?= $sym ?></button></form>
        <?php endforeach; ?>
        <form method="post" onsubmit="return confirm('Remove this slide?')"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="action" value="delete"><input type="hidden" name="i" value="<?= $i ?>"><button class="del" title="Remove">&#10005;</button></form>
      </div></div>
  <?php endforeach; ?>
  </div>
<?php endif; ?>
</div></body></html>
