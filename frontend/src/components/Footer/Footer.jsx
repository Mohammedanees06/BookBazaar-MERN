import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";

const Footer = () => {
  const [email, setEmail] = useState("");
  const [isSubscribed, setIsSubscribed] = useState(false);
  const [shouldHideFooter, setShouldHideFooter] = useState(false);

  useEffect(() => {
    const checkPath = () => {
      const currentPath = window.location.pathname.toLowerCase();
      const hiddenPaths = ['/login', '/signup'];
      const shouldHide = hiddenPaths.some(path =>
        currentPath === path || currentPath.startsWith(path + '/')
      );
      setShouldHideFooter(shouldHide);
    };

    checkPath();

    window.addEventListener('popstate', checkPath);
    window.addEventListener('hashchange', checkPath);

    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;

    history.pushState = function (...args) {
      originalPushState.apply(history, args);
      setTimeout(checkPath, 0);
    };

    history.replaceState = function (...args) {
      originalReplaceState.apply(history, args);
      setTimeout(checkPath, 0);
    };

    return () => {
      window.removeEventListener('popstate', checkPath);
      window.removeEventListener('hashchange', checkPath);
      history.pushState = originalPushState;
      history.replaceState = originalReplaceState;
    };
  }, []);

  if (shouldHideFooter) return null;

  const handleNewsletterSubmit = () => {
    if (email) {
      setIsSubscribed(true);
      setEmail("");
      setTimeout(() => setIsSubscribed(false), 3000);
    }
  };

  const scrollToTop = () => window.scrollTo({ top: 0, behavior: 'smooth' });

  const navAndScroll = () => {
    scrollToTop();
  };

  return (
    <footer className="bg-zinc-900 text-white relative overflow-hidden">
      {/* Top border line ✅ */}
      <div className="absolute top-0 left-0 right-0 h-px bg-zinc-700"></div>

      <div className="relative z-10 max-w-7xl mx-auto px-8 py-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12">

          {/* Brand Section */}
          <div className="space-y-6">
            <div className="flex items-center space-x-3">
              <div className="bg-zinc-800 p-2 rounded-lg border border-zinc-700">📚</div>
              <h2 className="text-3xl font-bold text-white">BookBazaar</h2>
            </div>
            <p className="text-zinc-300 leading-relaxed">
              Your ultimate destination for books. Discover, explore, and immerse yourself in worlds of knowledge and imagination.
            </p>
            <div className="flex space-x-4">
              {["📘", "🐦", "📸", "▶️"].map((icon, i) => (
                <button
                  key={i}
                  className="bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 hover:border-zinc-600 p-3 rounded-full"
                >
                  {icon}
                </button>
              ))}
            </div>
          </div>

          {/* Quick Links */}
          <div className="space-y-6">
            <h3 className="text-xl font-semibold text-white border-b border-zinc-700 pb-2">Quick Links</h3>
            <ul className="space-y-3">
              {["Browse Books", "New Arrivals", "Categories", "Authors", "Reviews"].map((link) => (
                <li key={link}>
                  {["Browse Books", "New Arrivals", "Categories"].includes(link) ? (
                    <Link
                      to="/all-books"
                      onClick={navAndScroll}
                      className="text-zinc-300 hover:text-white transition-colors duration-200 flex items-center space-x-2 group"
                    >
                      <span className="w-1 h-1 bg-zinc-400 rounded-full opacity-0 group-hover:opacity-100 transition-opacity"></span>
                      <span>{link}</span>
                    </Link>
                  ) : (
                    <a
                      href="#"
                      className="text-zinc-300 hover:text-white transition-colors duration-200 flex items-center space-x-2 group"
                    >
                      <span className="w-1 h-1 bg-zinc-400 rounded-full opacity-0 group-hover:opacity-100 transition-opacity"></span>
                      <span>{link}</span>
                    </a>
                  )}
                </li>
              ))}
            </ul>
          </div>

          {/* Support */}
          <div className="space-y-6">
            <h3 className="text-xl font-semibold text-white border-b border-zinc-700 pb-2">Support</h3>
            <div className="space-y-4 text-zinc-300">
              <div className="flex items-center space-x-3">📞 <span>+1 (555) 123-BOOK</span></div>
              <div className="flex items-center space-x-3">✉️ <span>cdacsupport@bookbazaar.com</span></div>
              <div className="flex items-start space-x-3">📍 <span>C-DAC BookStore <br />Electronic City, Phase1, Bangalore</span></div>
            </div>
            <div className="space-y-2">
              <h4 className="font-medium text-white">Business Hours</h4>
              <p className="text-zinc-400 text-sm">Mon-Fri: 9AM-6PM<br />Sat-Sun: 10AM-6PM</p>
            </div>
          </div>

          {/* Newsletter */}
          <div className="space-y-6">
            <h3 className="text-xl font-semibold text-white border-b border-zinc-700 pb-2">Stay Updated</h3>
            <p className="text-zinc-300">Subscribe for recommendations and deals.</p>
            <div className="space-y-4">
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your email"
                className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-white placeholder-zinc-400"
              />
              <button
                onClick={handleNewsletterSubmit}
                className="w-full bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-white py-3 px-6 rounded-lg"
                disabled={isSubscribed}
              >
                {isSubscribed ? "Thank you!" : "Subscribe"}
              </button>
            </div>
            <div className="space-y-2">
              <h4 className="text-sm font-medium text-zinc-400">We Accept</h4>
              <div className="flex space-x-2">
                {['VISA', 'MC', 'AMEX', 'PayPal'].map((pay) => (
                  <div key={pay} className="bg-zinc-800 px-2 py-1 rounded text-xs text-zinc-300 border border-zinc-700">{pay}</div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Bottom */}
        <div className="border-t border-zinc-800 mt-12 pt-8">
          <div className="flex flex-col lg:flex-row justify-between items-center space-y-4 lg:space-y-0">
            <div className="text-center lg:text-left">
              <p className="text-zinc-400">&copy; 2025 BookBazaar. All Rights Reserved.</p>
              <p className="text-sm text-zinc-500 mt-1">Made with ❤️ for book lovers everywhere</p>
            </div>
            <div className="flex flex-wrap justify-center lg:justify-end space-x-6 text-sm">
              {['Privacy Policy', 'Terms of Service', 'Cookie Policy', 'Sitemap'].map((link) => (
                <a key={link} href="#" className="text-zinc-400 hover:text-white transition-colors duration-200">
                  {link}
                </a>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Scroll to Top FAB */}
      <button
        onClick={scrollToTop}
        className="absolute bottom-8 right-8 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-white p-3 rounded-full"
        aria-label="Scroll to top"
      >
        ⬆️
      </button>
    </footer>
  );
};

export default Footer;
