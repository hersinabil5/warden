# Dashboard showcase on Vercel

The showcase is Warden's admin dashboard built as a static site with sample data
(docs/DECISIONS.md D31): sessions, an audit log full of blocked attacks, and the routes, all
in the browser with no Warden behind it. Revoking works until you reload. It's the link that
can't break.

## Try it locally

```sh
make showcase
cd web/admin && npm run preview:showcase   # http://localhost:4173
```

## Deploy (free Hobby plan)

1. Sign up at <https://vercel.com> with your GitHub account.
2. **Add New → Project**, import the `warden` repository.
3. Settings:
   - **Root Directory:** `web/admin`
   - **Framework Preset:** Other (`web/admin/vercel.json` sets install, build, output, and headers)
4. **Deploy.** Every push to `main` redeploys.
5. Optional: under **Settings → Environment Variables**, set `VITE_LIVE_DEMO_URL` to the live
   demo's landing page (the auth host root, demo mode, D30) once it runs, then redeploy. The
   banner gets a "Try the live system" link.

## Embedding in another site

`vercel.json` sends `frame-ancestors 'none'`, so nothing can frame the showcase. To embed it
(for example on a portfolio page), replace `'none'` with that site's origin, such as
`frame-ancestors https://your-portfolio.example`, rather than allowing any origin.
