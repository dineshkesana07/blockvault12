import React from 'react';
import { Link } from 'react-router-dom';

export default function Landing() {
  return (
    <main className="min-h-[calc(100vh-3.5rem)]">
      <section className="flex flex-col items-center justify-center px-6 py-32 md:py-40">
        <h1 className="font-serif font-bold text-4xl md:text-5xl text-charcoal text-center leading-tight">
          Your credentials,<br />cryptographically yours.
        </h1>
        <p className="mt-6 max-w-[55ch] text-center text-stone text-base leading-relaxed">
          BlockVault encrypts every password locally before it ever leaves
          your device. No cloud keys. No trust required. Just math.
        </p>
        <div className="mt-10 flex items-center gap-4">
          <Link
            to="/signup"
            className="px-5 py-2.5 bg-charcoal text-paper text-sm font-medium rounded hover:bg-ash duration-100"
          >
            Create vault
          </Link>
          <Link
            to="/login"
            className="px-5 py-2.5 border border-charcoal text-charcoal text-sm font-medium rounded hover:bg-charcoal hover:text-paper duration-100"
          >
            Log in
          </Link>
        </div>
      </section>

      <section className="border-t border-chalk">
        <div className="mx-auto max-w-3xl px-6 py-20 md:py-28">
          <div className="space-y-16">
            <div>
              <h2 className="font-serif font-medium text-xl text-charcoal">Local-first encryption</h2>
              <p className="mt-3 max-w-[60ch] text-stone text-sm leading-relaxed">
                Your master password derives an encryption key on your device.
                Credentials are encrypted with AES-256 before any network
                request is made. The server stores ciphertext it cannot read.
              </p>
            </div>
            <div>
              <h2 className="font-serif font-medium text-xl text-charcoal">Zero-knowledge architecture</h2>
              <p className="mt-3 max-w-[60ch] text-stone text-sm leading-relaxed">
                We never receive, store, or transmit your master password.
                Authentication uses a derived proof — even a compromised
                server reveals nothing about your vault contents.
              </p>
            </div>
            <div>
              <h2 className="font-serif font-medium text-xl text-charcoal">Organized by default</h2>
              <p className="mt-3 max-w-[60ch] text-stone text-sm leading-relaxed">
                Categories, favorites, and search keep your credentials
                accessible without friction. One vault, no clutter, instant
                retrieval.
              </p>
            </div>
          </div>
        </div>
      </section>

      <footer className="border-t border-chalk px-6 py-8">
        <p className="text-center text-stone text-xs">
          BlockVault — open-source credential management
        </p>
      </footer>
    </main>
  );
}
