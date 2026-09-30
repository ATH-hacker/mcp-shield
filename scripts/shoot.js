/**
 * 用 playwright-core 驱动本机已装 Chrome，对 MCP Shield 控制台逐页签截图。
 * 不使用浏览器下载：executablePath 指向系统 Chrome。
 *
 * 用法: node scripts/shoot.js <baseUrl> <outDir>
 *   baseUrl 例如 http://127.0.0.1:8787
 */
const path = require("path");
const fs = require("fs");
const { chromium } = require("playwright-core");

const CHROME_CANDIDATES = [
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
];

const baseUrl = process.argv[2] || "http://127.0.0.1:8787";
const outDir = process.argv[3] || path.join(__dirname, "..", "docs", "shots");

async function main() {
  const exe = CHROME_CANDIDATES.find((p) => fs.existsSync(p));
  if (!exe) throw new Error("找不到 Chrome / Edge 可执行文件");
  fs.mkdirSync(outDir, { recursive: true });
  console.log("chrome   =", exe);
  console.log("baseUrl  =", baseUrl);
  console.log("outDir   =", outDir);

  const browser = await chromium.launch({
    executablePath: exe,
    args: ["--force-color-profile=srgb", "--hide-scrollbars"],
  });
  const page = await browser.newPage({
    viewport: { width: 1680, height: 1050 },
    deviceScaleFactor: 2,
  });

  // 控制台会把真实报错打到页面 console，抓下来便于排查
  page.on("console", (m) => {
    if (m.type() === "error") console.log("  [page error]", m.text());
  });
  page.on("pageerror", (e) => console.log("  [page exception]", e.message));

  const shoot = async (viewId, file, prep) => {
    await page.goto(`${baseUrl}/?v=${viewId}`, { waitUntil: "load", timeout: 60000 });
    await page.waitForTimeout(1200);
    if (prep) await prep();
    const target = path.join(outDir, file);
    await page.screenshot({ path: target, fullPage: true });
    const bytes = fs.statSync(target).size;
    console.log(`  ✓ ${file}  ${bytes} B`);
  };

  // ① 以前做不到什么
  await shoot("v-before", "01_before.png");

  // ② 同一条描述 · 三个世界 —— 做成 2x2：get_weather(零宽) / send_email(TAG)
  await shoot("v-detect", "02_world_get_weather.png");
  await shoot("v-detect", "02_world_send_email.png", async () => {
    await page.locator('.toolitem[data-n="send_email"]').click();
    await page.waitForTimeout(600);
  });
  await shoot("v-detect", "02_world_transfer_funds.png", async () => {
    await page.locator('.toolitem[data-n="transfer_funds"]').click();
    await page.waitForTimeout(600);
  });
  await shoot("v-detect", "02_world_read_file.png", async () => {
    await page.locator('.toolitem[data-n="read_file"]').click();
    await page.waitForTimeout(600);
  });

  // ③ 怎么做到的
  await shoot("v-how", "03_how.png");

  // ④ 运行层取证实录 —— 现场点按钮，让页面真的去抓一次报文
  await shoot("v-run", "04_run_capture.png", async () => {
    await page.click("#btn-run-attack");
    await page.waitForFunction(
      () => {
        const s = document.getElementById("run-status");
        return s && /完成|失败/.test(s.textContent);
      },
      { timeout: 90000 }
    );
    await page.waitForTimeout(500);
    const txt = await page.locator("#run-status").innerText();
    console.log("    run-status:", txt.trim());
  });

  // ⑤ 一句话结论
  await shoot("v-inno", "05_conclusion.png");

  await browser.close();
  console.log("done.");
}

main().catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
