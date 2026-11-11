package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/nexssp/testkit"
)

func TestLocalHostAuthHTTPAndProtectedFlows(t *testing.T) {
	app, err := newLocalApp()
	if err != nil {
		t.Fatal(err)
	}
	suite := testkit.NewWithHandler(t, app)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := suite.Server.Client()
	client.Jar = jar

	password := "correct horse battery staple"
	registerBody := `{"email":"alex@example.test","username":"alex","password":"` + password + `","confirmation":"` + password + `","terms_accepted":true}`
	response := postJSON(t, client, suite.Server.URL+"/auth/register", registerBody)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want %d: %s", response.StatusCode, http.StatusCreated, readBody(t, response))
	}
	registerResult := readBody(t, response)
	if !strings.Contains(registerResult, `"registered":true`) || !strings.Contains(registerResult, `"authenticated":true`) {
		t.Fatalf("register response = %s", registerResult)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, suite.Server.URL+"/auth/session", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("host auth session status = %d: %s", response.StatusCode, readBody(t, response))
	}
	var apiIdentity map[string]any
	if err := json.Unmarshal([]byte(readBody(t, response)), &apiIdentity); err != nil {
		t.Fatal(err)
	}
	if apiIdentity["account_id"] != "1" {
		t.Fatalf("host auth session identity = %#v", apiIdentity)
	}

	forgedClient := &http.Client{}
	forgedRequest, err := http.NewRequestWithContext(context.Background(), http.MethodGet, suite.Server.URL+"/auth/session", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	forgedRequest.Header.Set("X-User-Id", "1")
	response, err = forgedClient.Do(forgedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged host auth session identity status = %d, want 401: %s", response.StatusCode, readBody(t, response))
	}
	_ = readBody(t, response)

	response = postJSON(t, client, suite.Server.URL+"/flow/current-session", `{}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("current-session status = %d: %s", response.StatusCode, readBody(t, response))
	}
	var identity map[string]any
	if err := json.Unmarshal([]byte(readBody(t, response)), &identity); err != nil {
		t.Fatal(err)
	}
	if identity["account_id"] != "1" || identity["email_verified"] != true {
		t.Fatalf("current identity = %#v", identity)
	}

	response = postJSON(t, client, suite.Server.URL+"/flow/authorized-report", `{}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authorized report status = %d: %s", response.StatusCode, readBody(t, response))
	}
	var report map[string]string
	if err := json.Unmarshal([]byte(readBody(t, response)), &report); err != nil {
		t.Fatal(err)
	}
	if report["report"] == "" {
		t.Fatalf("report response = %#v", report)
	}

	response = postJSON(t, client, suite.Server.URL+"/flow/accountant-invoices", `{}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("accountant invoice list status = %d: %s", response.StatusCode, readBody(t, response))
	}
	var invoiceList invoiceListResponse
	if err := json.Unmarshal([]byte(readBody(t, response)), &invoiceList); err != nil {
		t.Fatal(err)
	}
	if invoiceList.Total != 1 || len(invoiceList.Data) != 1 || invoiceList.Data[0].InvoiceNumber != "FV/2026/001" {
		t.Fatalf("accountant invoice list = %#v, want only the standard invoice in the authenticated workspace", invoiceList)
	}
	if invoiceList.Data[0].CustomerName != "Northwind Components Sp. z o.o." || invoiceList.Data[0].Currency != "PLN" || invoiceList.Data[0].Total != 1230.50 {
		t.Fatalf("invoice summary = %#v", invoiceList.Data[0])
	}
	if len(invoiceList.Years) != 1 || invoiceList.Years[0] != "2026" {
		t.Fatalf("invoice years = %#v", invoiceList.Years)
	}

	// Tenant and role fields in caller JSON cannot override the trusted host context.
	response = postJSON(t, client, suite.Server.URL+"/flow/accountant-invoices", `{"tenant_id":"southwind-demo","roles":["tenant_admin"]}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("forged invoice-list request status = %d: %s", response.StatusCode, readBody(t, response))
	}
	var forgedInvoiceList invoiceListResponse
	if err := json.Unmarshal([]byte(readBody(t, response)), &forgedInvoiceList); err != nil {
		t.Fatal(err)
	}
	if forgedInvoiceList.Total != 1 || len(forgedInvoiceList.Data) != 1 || forgedInvoiceList.Data[0].InvoiceNumber != "FV/2026/001" {
		t.Fatalf("caller-supplied tenant or role changed invoice scope: %#v", forgedInvoiceList)
	}

	app.grants.set("1", grant{roles: []string{"analyst"}, permissions: []string{"reports:read"}, organizationID: "northwind-demo"})
	response = postJSON(t, client, suite.Server.URL+"/flow/accountant-invoices", `{}`)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("invoice list without viewer role status = %d, want 403: %s", response.StatusCode, readBody(t, response))
	}

	// The app's fake policy is the only source of these grants; omit each one in
	// turn to prove both Flow guards are active and independent.
	app.grants.set("1", grant{permissions: []string{"reports:read"}})
	response = postJSON(t, client, suite.Server.URL+"/flow/authorized-report", `{}`)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("report without role status = %d, want 403: %s", response.StatusCode, readBody(t, response))
	}
	app.grants.set("1", grant{roles: []string{"analyst"}})
	response = postJSON(t, client, suite.Server.URL+"/flow/authorized-report", `{}`)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("report without permission status = %d, want 403: %s", response.StatusCode, readBody(t, response))
	}
	response = postJSON(t, client, suite.Server.URL+"/flow/authorized-report", `{"roles":["admin"],"permissions":["reports:read"]}`)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("caller-supplied grant bypassed host policy: status=%d, want 403: %s", response.StatusCode, readBody(t, response))
	}

	response = postJSON(t, client, suite.Server.URL+"/auth/logout", `{}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d: %s", response.StatusCode, readBody(t, response))
	}
	loginBody := `{"identifier":"alex@example.test","password":"` + password + `"}`
	response = postJSON(t, client, suite.Server.URL+"/auth/login", loginBody)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d: %s", response.StatusCode, readBody(t, response))
	}
	loginResult := readBody(t, response)
	if !strings.Contains(loginResult, `"authenticated":true`) || !strings.Contains(loginResult, `"credential_type":"browser_session"`) {
		t.Fatalf("login response = %s", loginResult)
	}

	anonymous := &http.Client{}
	response = postJSON(t, anonymous, suite.Server.URL+"/flow/authorized-report", `{"roles":["analyst"],"permissions":["reports:read"]}`)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("caller-supplied grant without a session status = %d, want 401: %s", response.StatusCode, readBody(t, response))
	}
	response = postJSON(t, anonymous, suite.Server.URL+"/flow/accountant-invoices", `{"tenant_id":"northwind-demo","roles":["viewer"]}`)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("accountant invoice list without a session status = %d, want 401: %s", response.StatusCode, readBody(t, response))
	}
}

func postJSON(t *testing.T, client *http.Client, endpoint, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
