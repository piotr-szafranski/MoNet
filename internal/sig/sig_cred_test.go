package sig

import "testing"

func TestSafePath(t *testing.T) {
	bad := []string{"/x?u=a&p=b", "/x?access_token=1", "/x?usr=a&pwd2=b", "/l?username=admin&password=admin", "/a;jsessionid=1",
		"/a?API_KEY=1", "/x?name=admin&haslo=admin", "/x?a=admin&b=admin", "/login/admin/admin", "/cgi/admin/admin", "/%61dmin/%61dmin", "/admin/admin123", "/x/root/toor"}
	for _, p := range bad {
		if safePath(p) == nil {
			t.Errorf("przepuszczone: %s", p)
		}
	}
	good := []string{"/api/version", "/wp-login.php", "/status?format=json", "/admin", "/login", "/manager/html", "/.git/HEAD", "/index.php?page=1", "/auth/login", "/auth/realms/master", "/api/auth/session", "/session/new", "/admin/login", "/user/login"}
	for _, p := range good {
		if err := safePath(p); err != nil {
			t.Errorf("fałszywie zablokowane %s: %v", p, err)
		}
	}
}
