// motyw przed renderem (bez mignięcia): jasny tylko, gdy użytkownik go wybrał
try { if (localStorage.getItem('monet-theme') === 'light') document.documentElement.classList.add('light'); } catch (e) { /* brak dostępu do pamięci */ }
