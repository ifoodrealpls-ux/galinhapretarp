const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const { onCall, HttpsError } = require("firebase-functions/v2/https");

initializeApp();

const db = getFirestore();
const auth = getAuth();
const OWNER_EMAIL = "lucaspolicarpodeassis@gmail.com";

exports.createAdminAccount = onCall(async (request) => {
  const caller = request.auth;

  if (!caller) {
    throw new HttpsError("unauthenticated", "Faça login antes de criar um administrador.");
  }

  const callerEmail = String(caller.token.email || "").toLowerCase();
  if (callerEmail !== OWNER_EMAIL) {
    throw new HttpsError("permission-denied", "Somente o OWNER pode criar administradores.");
  }

  const { name, email, password, role } = request.data || {};
  const cleanName = String(name || "").trim();
  const cleanEmail = String(email || "").trim().toLowerCase();
  const cleanPassword = String(password || "");
  const allowedRoles = new Set(["admin", "moderator", "support"]);

  if (!cleanName || !cleanEmail || !cleanPassword) {
    throw new HttpsError("invalid-argument", "Nome, e-mail e senha são obrigatórios.");
  }

  if (!allowedRoles.has(role)) {
    throw new HttpsError("invalid-argument", "Cargo administrativo inválido.");
  }

  if (cleanPassword.length < 6) {
    throw new HttpsError("invalid-argument", "A senha precisa ter pelo menos 6 caracteres.");
  }

  try {
    const userRecord = await auth.createUser({
      email: cleanEmail,
      password: cleanPassword,
      displayName: cleanName,
      disabled: false
    });

    await auth.setCustomUserClaims(userRecord.uid, { role });

    await db.collection("admins").doc(userRecord.uid).set({
      uid: userRecord.uid,
      name: cleanName,
      email: cleanEmail,
      role,
      status: "active",
      createdBy: caller.uid,
      createdAt: FieldValue.serverTimestamp()
    });

    await db.collection("adminLogs").add({
      action: "admin_created",
      targetUid: userRecord.uid,
      targetEmail: cleanEmail,
      role,
      performedBy: caller.uid,
      createdAt: FieldValue.serverTimestamp()
    });

    return {
      ok: true,
      uid: userRecord.uid,
      message: "Administrador criado com sucesso."
    };
  } catch (error) {
    console.error("createAdminAccount failed", error);

    if (error.code === "auth/email-already-exists") {
      throw new HttpsError("already-exists", "Já existe uma conta com esse e-mail.");
    }

    if (error instanceof HttpsError) {
      throw error;
    }

    throw new HttpsError("internal", "Não foi possível criar o administrador.");
  }
});
