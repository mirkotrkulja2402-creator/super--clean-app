const app = document.getElementById("app");

const mainMenu = [
  ["➕", "Nova narudžba", "Brzo zaprimanje tepiha", "orders.view"],
  ["👥", "Kupci", "Kupci i kontakt podaci", "customers.view"],
  ["📋", "Narudžbe", "Pregled i statusi", "orders.view"],
  ["💰", "Cjenovnik", "Usluge i cijene", "pricing.view"],
  ["🏷️", "Etikete", "Štampanje etiketa", "labels.view"],
  ["📷", "QR kod", "Kreiranje i skeniranje", "qr.view"],
  ["🧾", "Računi", "Računi i fakture", "invoices.view"],
  ["📊", "Izvještaji", "Pregled poslovanja", "reports.view"],
];

const permissionGroups = [
  [
    "Kupci",
    [
      ["customers.view", "Pregled kupaca"],
      ["customers.create", "Dodavanje kupaca"],
      ["customers.edit", "Izmjena kupaca"],
      ["customers.delete", "Brisanje kupaca"],
    ],
  ],
  [
    "Narudžbe",
    [
      ["orders.view", "Pregled narudžbi"],
      ["orders.create", "Dodavanje narudžbi"],
      ["orders.edit", "Izmjena narudžbi"],
      ["orders.delete", "Brisanje narudžbi"],
    ],
  ],
  [
    "Cjenovnik",
    [
      ["pricing.view", "Pregled cjenovnika"],
      ["pricing.edit", "Izmjena cjenovnika"],
    ],
  ],
  [
    "Etikete i QR",
    [
      ["labels.view", "Pregled etiketa"],
      ["labels.print", "Štampanje etiketa"],
      ["qr.view", "Pregled QR kodova"],
      ["qr.create", "Kreiranje QR kodova"],
    ],
  ],
  [
    "Računi",
    [
      ["invoices.view", "Pregled računa"],
      ["invoices.create", "Kreiranje računa"],
      ["invoices.edit", "Izmjena računa"],
      ["invoices.print", "Štampanje računa"],
    ],
  ],
  [
    "Izvještaji",
    [
      ["reports.view", "Pregled izvještaja"],
      ["reports.export", "Izvoz izvještaja"],
    ],
  ],
  [
    "Excel",
    [
      ["excel.import", "Uvoz Excel podataka"],
      ["excel.export", "Izvoz Excel podataka"],
    ],
  ],
  [
    "Administracija",
    [
      ["admin.users", "Upravljanje korisnicima"],
      ["admin.roles", "Upravljanje ulogama i dozvolama"],
      ["admin.settings", "Podešavanja aplikacije"],
    ],
  ],
];

let currentUser = null;
let rolesData = [];
let permissionsData = [];

let currentPage = "home";
let activeAdminTab = "users";
let selectedRecord = null;

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function hasPermission(code) {
  return (
    currentUser?.role === "ADMIN" || currentUser?.permissions?.includes(code)
  );
}

const SC_REFERENCE_STYLE_ID = "sc-reference-ui-style";

function scSvg(icon, label = "") {
  const paths = {
    menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
    user: '<circle cx="12" cy="8" r="3.5"/><path d="M5 20c.8-3.3 3.2-5 7-5s6.2 1.7 7 5"/>',
    search: '<circle cx="10.8" cy="10.8" r="6.2"/><path d="m16 16 4.2 4.2"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    recycle:
      '<path d="m8 5-3 5h4l-2 3 5 6 2-5h4l-3-5"/><path d="m15 5 3 3-3 3"/><path d="M18 8h-5"/>',
    trash: '<path d="M5 7h14M9 7V4h6v3M8 10v7M12 10v7M16 10v7M7 20h10"/>',
    print:
      '<path d="M7 9V4h10v5M7 16h10v4H7z"/><path d="M5 9h14a2 2 0 0 1 2 2v5h-4M3 16v-5a2 2 0 0 1 2-2"/>',
    file: '<path d="M7 3h7l4 4v14H7z"/><path d="M14 3v5h5M10 12h5M10 16h5"/>',
    clipboard:
      '<path d="M9 4h6M9 3v3h6V3M6 5h12v16H6z"/><path d="M9 11h6M9 15h6"/>',
    users:
      '<circle cx="9" cy="9" r="3"/><circle cx="16.5" cy="10" r="2.5"/><path d="M3.5 20c.5-3.3 2.3-5 5.5-5s5 1.7 5.5 5M14 15.5c3.2-.1 5 1.5 5.5 4.5"/>',
    tag: '<path d="M4 5v7l8 8 8-8-8-8z"/><circle cx="8.5" cy="8.5" r="1.2"/>',
    qr: '<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4z"/><path d="M14 14h3v3h-3zM18 18h2v2h-2zM17 14h3"/>',
    chart: '<path d="M4 19V5M4 19h17"/><path d="m7 15 4-5 3 3 5-7"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.2-1.6l2-1.2-2-3.4-2.1 1.1a7 7 0 0 0-2.8-1.6L13.7 3h-3.4l-.3 2.3a7 7 0 0 0-2.8 1.6L5.1 5.8l-2 3.4 2 1.2A7 7 0 0 0 5 12c0 .6.1 1.1.2 1.6l-2 1.2 2 3.4 2.1-1.1a7 7 0 0 0 2.8 1.6l.3 2.3h3.4l.3-2.3a7 7 0 0 0 2.8-1.6l2.1 1.1 2-3.4-2-1.2c.1-.5.2-1 .2-1.6z"/>',
    shield:
      '<path d="M12 3 19 6v5c0 4.4-2.8 7.6-7 10-4.2-2.4-7-5.6-7-10V6z"/><path d="m9 12 2 2 4-4"/>',
    eye: '<path d="M2.5 12s3.2-5 9.5-5 9.5 5 9.5 5-3.2 5-9.5 5-9.5-5-9.5-5z"/><circle cx="12" cy="12" r="2.5"/>',
    eyeOff:
      '<path d="M3 3l18 18M9.9 5.3A10.7 10.7 0 0 1 12 5c6.3 0 9.5 7 9.5 7a16 16 0 0 1-2.5 3.4M6.2 6.3C3.9 7.9 2.5 12 2.5 12s3.2 7 9.5 7c1.6 0 3-.4 4.2-1"/>',
    home: '<path d="m3 11 9-7 9 7v9h-6v-6H9v6H3z"/>',
  };

  return ` <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-label="${escapeHtml( label )}" role="img"> ${paths[icon] || paths.file} </svg> `;
}

function scMenuIcon(title) {
  const icons = {
    "Nova narudžba": "plus",
    Kupci: "users",
    Narudžbe: "clipboard",
    Cjenovnik: "tag",
    Etikete: "tag",
    "QR kod": "qr",
    Računi: "file",
    Izvještaji: "chart",
    Administrator: "gear",
  };
  return scSvg(icons[title] || "file", title);
}

function loginView(error = "") {
  app.innerHTML = ` <main class="sc-reference-login"> <section class="sc-reference-login-card"> <div class="sc-reference-login-brand"> <img class="sc-reference-login-logo" src="/logo-login.png" alt="Super Clean" > <h1>Super Clean</h1> <p>Banja Luka · poslovna aplikacija</p> </div> <div id="login-error" class="error login-error${ error ? "" : " hidden" }">${escapeHtml( error )}</div> <form id="login-form" class="sc-reference-login-form" novalidate> <label class="sc-reference-field"> <span class="sc-reference-field-label"> ${scSvg( "user", "Korisničko ime" )} Korisničko ime </span> <span class="sc-reference-input-wrap"> <input name="username" autocomplete="username" placeholder="Unesite korisničko ime" required autofocus > </span> </label> <label class="sc-reference-field"> <span class="sc-reference-field-label"> ${scSvg( "shield", "Šifra" )} Šifra </span> <span class="sc-reference-input-wrap"> <input id="login-password" name="password" type="password" autocomplete="current-password" placeholder="Unesite šifru" required > <button type="button" class="sc-reference-password-toggle" id="password-toggle" aria-label="Prikaži šifru" aria-pressed="false" >${scSvg( "eye", "Prikaži šifru" )}</button> </span> </label> <div class="sc-reference-login-options"> <span class="sc-remember"> <span class="sc-remember-mark">✓</span> Zapamti me na ovom uređaju </span> <button type="button" class="sc-change-user" id="change-user-button" > ${scSvg( "gear", "Promijeni korisnika" )} Promijeni korisnika </button> </div> <button class="sc-reference-login-submit" id="login-button" type="submit" > PRIJAVI SE &nbsp; → </button> <div class="sc-reference-secure"> ${scSvg( "shield", "Sigurna prijava" )} Sigurna prijava </div> </form> <div class="sc-reference-login-footer"> Čist dom • Zdraviji život </div> </section> </main> `;

  document.getElementById("login-form").addEventListener("submit", handleLogin);

  document.getElementById("password-toggle").addEventListener("click", () => {
    const passwordInput = document.getElementById("login-password");
    const toggle = document.getElementById("password-toggle");
    const visible = passwordInput.type === "text";

    passwordInput.type = visible ? "password" : "text";
    toggle.innerHTML = scSvg(
      visible ? "eye" : "eyeOff",
      visible ? "Prikaži šifru" : "Sakrij šifru"
    );
    toggle.setAttribute(
      "aria-label",
      visible ? "Prikaži šifru" : "Sakrij šifru"
    );
    toggle.setAttribute("aria-pressed", String(!visible));
  });

  document
    .getElementById("change-user-button")
    .addEventListener("click", logout);
}

function dashboardView(user) {
  currentUser = user;

  const sidebarItems = mainMenu
    .filter(([, , , permission]) => hasPermission(permission))
    .map(([icon, title, description]) => ({
      title,
      description,
    }));

  if (user.role === "ADMIN") {
    sidebarItems.push({
      title: "Administrator",
      description: "Upravljanje aplikacijom",
    });
  }

  const sidebarHtml = sidebarItems
    .map(
      (item) =>
        ` <button type="button" class="sc-sidebar-item ${ item.title === "Nova narudžba" ? "" : "" }" data-page-label="${escapeHtml(item.title)}" > ${scMenuIcon( item.title )} <span>${escapeHtml(item.title)}</span> </button> `
    )
    .join("");

  app.innerHTML = ` <div class="sc-reference-app"> <header class="sc-app-header"> <button type="button" class="sc-header-menu-button" id="menu-toggle" aria-label="Meni" > ${scSvg( "menu", "Meni" )} </button> <div class="sc-header-brand"> <img src="/logo-login.png" alt="Super Clean"> </div> <div class="sc-header-search"> ${scSvg( "search", "Pretraži" )} <input id="global-search-desktop" placeholder="Pretraži..." aria-label="Pretraži" autocomplete="off" > </div> <div class="sc-header-actions"> <button type="button" class="sc-header-action" data-action="remove" aria-label="Ukloni"> ${scSvg( "trash", "Ukloni" )} </button> <button type="button" class="sc-header-action" data-action="print" aria-label="Štampaj"> ${scSvg( "print", "Štampaj" )} </button> <button type="button" class="sc-header-action" data-action="pdf" aria-label="PDF"> ${scSvg( "file", "PDF" )} </button> <button type="button" class="sc-header-action" data-action="search" aria-label="Pretraga"> ${scSvg( "search", "Pretraga" )} </button> <button type="button" class="sc-header-action" id="more-actions" aria-label="Više"> ${scSvg( "menu", "Više" )} </button> <button type="button" class="sc-user-button" id="user-menu" aria-label="Korisnik"> <span class="sc-user-avatar">${scSvg( "user", "Korisnik" )}</span> <span>${escapeHtml( user.firstName || "Korisnik" )}</span> </button> </div> </header> <div class="sc-layout"> <aside class="sc-sidebar"> <div class="sc-sidebar-list"> <button type="button" class="sc-sidebar-item active" data-page="home" > ${scSvg( "home", "Početna" )} <span>Početna</span> </button> ${sidebarHtml} </div> </aside> <main class="sc-main"> <div class="sc-mobile-tools"> <div class="sc-mobile-search"> ${scSvg( "search", "Pretraži" )} <input id="global-search" placeholder="Pretraži..." aria-label="Pretraži" autocomplete="off" > </div> <div class="sc-mobile-toolbar" aria-label="Brze radnje"> <button type="button" data-action="add" aria-label="Dodaj"> ${scSvg( "plus", "Dodaj" )} <span>Dodaj</span> </button> <button type="button" data-action="remove" aria-label="Ukloni"> ${scSvg( "recycle", "Ukloni" )} <span>Ukloni</span> </button> <button type="button" data-action="print" aria-label="Štampaj"> ${scSvg( "print", "Štampaj" )} <span>Print</span> </button> <button type="button" data-action="pdf" aria-label="PDF"> ${scSvg( "file", "PDF" )} <span>PDF</span> </button> <button type="button" data-action="search" aria-label="Pretraga"> ${scSvg( "search", "Pretraga" )} <span>Pretraga</span> </button> <button type="button" id="mobile-more-actions" aria-label="Više"> ${scSvg( "menu", "Više" )} <span>Više</span> </button> </div> </div> <section id="page-content">${homeContent()}</section> </main> </div> <nav class="sc-mobile-bottom"> <button type="button" data-page="home" class="active"> ${scSvg( "home", "Početna" )} <span>Početna</span> </button> ${ hasPermission("orders.view") ? ` <button type="button" data-page="orders"> ${scSvg( "clipboard", "Narudžbe" )} <span>Narudžbe</span> </button> ` : "" } ${ hasPermission("customers.view") ? ` <button type="button" data-page="customers"> ${scSvg( "users", "Kupci" )} <span>Kupci</span> </button> ` : "" } ${ user.role === "ADMIN" ? ` <button type="button" data-page="admin"> ${scSvg( "gear", "Admin" )} <span>Admin</span> </button> ` : "" } </nav> <div id="drawer" class="drawer hidden"></div> <div id="modal-root"></div> <input id="excel-file" type="file" accept=".xlsx,.xls,.csv" class="hidden"> </div> `;

  bindDashboard();
  loadDashboard();
}

function homeContent() {
  const menuItems = mainMenu
    .filter(([, , , permission]) => hasPermission(permission))
    .filter(([, title]) => title !== "Nova narudžba")
    .map(([, title, description]) => ({
      title,
      description,
    }));

  if (currentUser.role === "ADMIN") {
    menuItems.push({
      title: "Administrator",
      description: "Upravljanje aplikacijom",
    });
  }

  const cards = [
    {
      title: "Nova narudžba",
      description: "Brzo zaprimanje tepiha",
      icon: "plus",
    },
    ...menuItems.map((item) => ({
      ...item,
      icon:
        {
          Kupci: "users",
          Narudžbe: "clipboard",
          Cjenovnik: "tag",
          Etikete: "tag",
          "QR kod": "qr",
          Računi: "file",
          Izvještaji: "chart",
          Administrator: "gear",
        }[item.title] || "file",
    })),
  ];

  const cardHtml = cards
    .map(
      (item) =>
        ` <button class="sc-home-card" type="button" data-page-label="${escapeHtml( item.title )}" > <span class="sc-home-card-icon"> ${scSvg( item.icon, item.title )} </span> <strong>${escapeHtml( item.title )}</strong> <small>${escapeHtml( item.description )}</small> <span class="sc-home-card-arrow" aria-hidden="true">→</span> </button> `
    )
    .join("");

  return ` <section class="sc-home-hero"> <div class="sc-home-welcome"> <span class="sc-home-eyebrow">DOBRO DOŠAO</span> <h1>${escapeHtml( currentUser.firstName || "Korisnik" )} 👋</h1> <span class="sc-role-badge"> ${scSvg( "shield", "Uloga" )} ${escapeHtml( currentUser.role === "ADMIN" ? "ADMINISTRATOR" : currentUser.role || "KORISNIK" )} </span> </div> <img class="sc-home-hero-logo" src="/logo-login.png" alt="Super Clean" > </section> <button class="sc-new-order" type="button" data-page-label="Nova narudžba" > <span class="sc-new-order-icon">+</span> <span class="sc-new-order-text"> <strong>NOVA NARUDŽBA</strong> <span>Brz prijem novog tepiha</span> </span> <span class="sc-new-order-arrow" aria-hidden="true">→</span> </button> <section class="sc-menu-heading"> <span class="sc-home-eyebrow">GLAVNI MENI</span> <h2>Šta želiš otvoriti?</h2> </section> <div class="sc-home-grid"> ${cardHtml} </div> <footer class="sc-home-footer"> <span>Čist dom</span> <b>•</b> <span>Zdraviji život</span> </footer> `;
}

function dashboardSummaryContent(summary) {
  const cards = [
    hasPermission("orders.view")
      ? ["📋", "Narudžbe", summary.orderCount, ""]
      : null,
    hasPermission("orders.view")
      ? ["🧼", "Tepisi", summary.carpetCount, ""]
      : null,
    hasPermission("invoices.view")
      ? [
          "🧾",
          "Fakturisano",
          summary.invoicedCount,
          formatKm(summary.invoicedTotal) + " KM",
        ]
      : null,
    hasPermission("orders.view")
      ? ["🚚", "Dostava", "", formatKm(summary.deliveryTotal) + " KM"]
      : null,
    hasPermission("customers.view")
      ? ["👥", "Novi kupci", summary.newCustomerCount, ""]
      : null,
  ].filter(Boolean);

  return cards.length
    ? cards
        .map(
          ([icon, label, value, detail]) =>
            ` <article class="dashboard-stat"> <span class="dashboard-stat-icon">${icon}</span> <div> <small>${label}</small> <strong>${ value === "" ? detail : value }</strong> ${ value !== "" && detail ? `<span>${detail}</span>` : "" } </div> </article> `
        )
        .join("")
    : '<div class="dashboard-loading">Nema dostupnih podataka za tvoje dozvole.</div>';
}

function dashboardWarningsContent(warnings) {
  if (!warnings.length) {
    return ` <div class="dashboard-ok"> <span>✅</span> <div><strong>Sve je uredno</strong><small>Nema otvorenih upozorenja za provjerene podatke.</small></div> </div> `;
  }

  return warnings
    .map(
      (warning) =>
        ` <button class="dashboard-warning" data-warning-page="${escapeHtml( warning.page )}"> <span class="dashboard-warning-icon">⚠️</span> <span> <strong>${escapeHtml( warning.label )}</strong> <small>${escapeHtml( warning.description )}</small> </span> <b>${warning.count} ›</b> </button> `
    )
    .join("");
}

async function loadDashboard() {
  const summaryBox = document.getElementById("dashboard-summary");
  const warningsBox = document.getElementById("dashboard-warnings");
  if (!summaryBox || !warningsBox) return;

  try {
    const data = await api("/api/dashboard/summary");
    summaryBox.innerHTML = dashboardSummaryContent(data.summary);
    warningsBox.innerHTML = dashboardWarningsContent(data.warnings);
    const date = new Date(`${data.date}T12:00:00`);
    document.getElementById("dashboard-date").textContent =
      new Intl.DateTimeFormat("bs-BA", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
      }).format(date);

    warningsBox.querySelectorAll("[data-warning-page]").forEach((button) => {
      button.addEventListener("click", () =>
        navigate(button.dataset.warningPage)
      );
    });
  } catch (error) {
    summaryBox.innerHTML = `<div class="error">${escapeHtml( error.message )}</div>`;
    warningsBox.innerHTML = ` <div class="dashboard-ok"> <span>⚠️</span> <div><strong>Pregled nije dostupan</strong><small>Pokušaj ponovo kasnije.</small></div> </div> `;
  }
}

function formatKm(value) {
  return Number(value || 0).toFixed(2);
}

function formatDateBs(value) {
  if (!value) return "";
  const parts = String(value).split("-");
  return parts.length === 3
    ? `${parts[2]}.${parts[1]}.${parts[0]}.`
    : String(value);
}

function invoiceNumber(order) {
  const year = String(
    order.invoiceIssuedAt ||
      order.orderDate ||
      new Date().toISOString().slice(0, 10)
  ).slice(2, 4);
  const sequence = order.invoiceNumber || order.orderNumber;
  return `1/${year}-${String(sequence).padStart(5, "0")}`;
}

function invoiceStatusLabel(order) {
  if (order.invoiceStatus === "CANCELLED") return "STORNIRANO";
  if (order.invoiceStatus === "INVOICED") return "FAKTURISANO";
  return "U PRIPREMI";
}

function invoiceStatusClass(order) {
  if (order.invoiceStatus === "CANCELLED") return "invoice-status-cancelled";
  if (order.invoiceStatus === "INVOICED") return "invoice-status-invoiced";
  return "invoice-status-preparing";
}

function paymentMethodLabel(method) {
  if (method === "bank") return "ŽIRALNO";
  if (method === "card") return "KARTIČNO";
  return "GOTOVINSKI";
}

function invoiceContent(order, items) {
  const itemsTotal = items.reduce(
    (sum, item) => sum + Number(item.total || 0),
    0
  );
  const deliveryPrice = Number(order.deliveryPrice || 0);
  const total = Number((itemsTotal + deliveryPrice).toFixed(2));
  const paymentMethod = order.invoicePaymentMethod || "cash";
  const saved = order.invoiceStatus === "INVOICED";
  const cancelled = order.invoiceStatus === "CANCELLED";

  const rows = items
    .map((item, index) => {
      const dimension =
        item.unit === "m2"
          ? `${item.lengthM} × ${item.widthM} m`
          : `${item.quantity} kom.`;
      const quantity =
        item.unit === "m2"
          ? Number(item.areaM2 || 0).toFixed(2)
          : Number(item.quantity || 0).toFixed(2);

      return ` <tr> <td>${index + 1}</td> <td> <strong>${escapeHtml( item.serviceName )}</strong> ${ item.note ? `<small>${escapeHtml(item.note)}</small>` : "" } </td> <td>${escapeHtml( dimension )}</td> <td class="text-right">${escapeHtml(quantity)}</td> <td>${ item.unit === "m2" ? "m²" : "kom." }</td> <td class="text-right">${formatKm( item.unitPrice )} KM</td> <td class="text-right"><strong>${formatKm( item.total )} KM</strong></td> </tr> `;
    })
    .join("");

  const deliveryRow =
    deliveryPrice > 0
      ? ` <tr> <td>${ items.length + 1 }</td> <td><strong>Dostava</strong></td> <td>—</td> <td class="text-right">1</td> <td>usl.</td> <td class="text-right">${formatKm( deliveryPrice )} KM</td> <td class="text-right"><strong>${formatKm( deliveryPrice )} KM</strong></td> </tr> `
      : "";

  return ` <section class="invoice-page"> <div class="invoice-toolbar no-print"> <button class="back-button" data-go-invoice-list>← Raču
