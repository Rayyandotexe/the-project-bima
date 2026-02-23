import base64
import time
import logging

from selenium import webdriver
from selenium.common.exceptions import WebDriverException, TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

logger = logging.getLogger("bima.screenshots")


def _make_options(width: int, height: int, headless_flag: str = "--headless") -> Options:
    opts = Options()
    opts.add_argument(headless_flag)
    opts.add_argument(f"--window-size={width},{height}")
    # common flags to improve stability in headless environments
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-background-networking")
    opts.add_argument("--disable-background-timer-throttling")
    opts.add_argument("--disable-features=VizDisplayCompositor")
    opts.add_experimental_option("excludeSwitches", ["enable-logging"])
    return opts


def screenshot_base64(url, width=1200, height=900, timeout=20):
    """Return a data URL string with PNG screenshot, or None on failure.

    This function tries a modern headless flag first, then falls back to the older
    `--headless` argument if the first attempt fails. Exceptions are logged.
    """
    last_err = None
    for headless_flag in ("--headless=new", "--headless"):
        opts = _make_options(width, height, headless_flag=headless_flag)
        service = Service(ChromeDriverManager().install())
        try:
            driver = webdriver.Chrome(service=service, options=opts)
        except WebDriverException as e:
            last_err = e
            logger.debug("Failed to start Chrome with %s: %s", headless_flag, e)
            continue

        try:
            driver.set_page_load_timeout(timeout)
            try:
                driver.get(url)
            except TimeoutException:
                logger.warning("Page load timeout for %s (flag=%s)", url, headless_flag)

            # wait for document readyState or a short fixed wait for heavy JS
            try:
                WebDriverWait(driver, min(5, max(2, int(timeout / 4)))).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                )
            except Exception:
                # fallback: short sleep to let JS settle
                time.sleep(1)

            png = driver.get_screenshot_as_png()
            b64 = base64.b64encode(png).decode("utf-8")
            return "data:image/png;base64," + b64
        except Exception as e:
            last_err = e
            logger.warning("Screenshot capture failed for %s (flag=%s): %s", url, headless_flag, e)
        finally:
            try:
                driver.quit()
            except Exception:
                pass

    logger.debug("All screenshot attempts failed for %s: %s", url, last_err)
    return None