import fs from "fs";
import xlsx from "xlsx";
import fetch from "node-fetch";

// ========= CONFIG =========
const KEYCLOAK_BASE = "http://localhost:8081";
const REALM = "secured-library";

// client اللي عملناه للاستيراد
const CLIENT_ID = "import-script";
const CLIENT_SECRET = "GW0skHZ1tYAcgIFTW3vZi7kX3Um83aA3";

// ملف الإكسيل
const EXCEL_PATH = "./Humans_Excel.xlsx";

// ==========================

// تحويل role من الإكسيل لـ Keycloak
function mapRole(excelRole) {
  if (excelRole === "RWX") return "full_crud";
  if (excelRole === "R__") return "read_only";
  return null;
}

// 1️⃣ جيب access token
async function getToken() {
  const res = await fetch(
    `${KEYCLOAK_BASE}/realms/${REALM}/protocol/openid-connect/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
    }
  );

  const data = await res.json();
  if (!res.ok) throw new Error(JSON.stringify(data, null, 2));
  return data.access_token;
}

// 2️⃣ اقرأ الإكسيل
function readExcel() {
  const wb = xlsx.readFile(EXCEL_PATH);
  const sheet = wb.Sheets[wb.SheetNames[0]];
  return xlsx.utils.sheet_to_json(sheet);
}

// 3️⃣ أنشئ User
async function createUser(token, user) {
  const res = await fetch(
    `${KEYCLOAK_BASE}/admin/realms/${REALM}/users`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: user.username,
        email: user.email,
        enabled: true,
        emailVerified: true,
      }),
    }
  );

  if (res.status !== 201 && res.status !== 409) {
    const t = await res.text();
    throw new Error(t);
  }
}

// 4️⃣ جيب userId
async function getUserId(token, username) {
  const res = await fetch(
    `${KEYCLOAK_BASE}/admin/realms/${REALM}/users?username=${username}`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  const data = await res.json();
  return data[0].id;
}

// 5️⃣ حط password
async function setPassword(token, userId, password) {
  await fetch(
    `${KEYCLOAK_BASE}/admin/realms/${REALM}/users/${userId}/reset-password`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        type: "password",
        value: password,
        temporary: false,
      }),
    }
  );
}

// 6️⃣ حط role
async function assignRole(token, userId, roleName) {
  const rolesRes = await fetch(
    `${KEYCLOAK_BASE}/admin/realms/${REALM}/roles/${roleName}`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  );

  const role = await rolesRes.json();

  await fetch(
    `${KEYCLOAK_BASE}/admin/realms/${REALM}/users/${userId}/role-mappings/realm`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify([role]),
    }
  );
}

// ========= MAIN =========
(async () => {
  try {
    const token = await getToken();
    const users = readExcel();

    for (const u of users) {
      console.log(`➡️ Creating user: ${u.username}`);

      await createUser(token, u);
      const userId = await getUserId(token, u.username);

      await setPassword(token, userId, u.password);

      const role = mapRole(u.role);
      if (role) {
        await assignRole(token, userId, role);
        console.log(`   ✅ Role assigned: ${role}`);
      } else {
        console.log("   ⚠️ No valid role");
      }
    }

    console.log("\n🎉 Import finished successfully!");
  } catch (err) {
    console.error("❌ Error:", err.message);
  }
})();
