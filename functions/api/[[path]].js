const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json;charset=utf-8",
      "cache-control": "no-store"
    }
  });

const b64 = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

async function signature(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return b64(
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(msg)
    )
  );
}

async function auth(req, env) {
  const tok = (req.headers.get("authorization") || "")
    .replace(/^Bearer /, "");

  const [expiry, sig] = tok.split(".");

  if (
    !expiry ||
    !sig ||
    !Number.isFinite(Number(expiry)) ||
    Number(expiry) < Date.now() ||
    !env.ADMIN_PASSWORD
  ) {
    return false;
  }

  const expected = await signature(env.ADMIN_PASSWORD, expiry);
  return sig === expected;
}

async function columns(env, table) {
  const result = await env.DB.prepare(
    `PRAGMA table_info(${table})`
  ).all();

  return new Set(result.results.map((x) => x.name));
}

function playerOutput(p) {
  return {
    ...p,
    birthday: p.birthday ?? p.date_of_birth ?? "",
    blood: p.blood ?? p.blood_group ?? "",
    photo: p.photo ?? p.photo_key ?? "",
    rank: p.rank ?? 0,
    notes: p.notes ?? ""
  };
}

function playerFields(p, cols, isNew) {
  const values = {};

  if (cols.has("name")) {
    values.name = String(p.name || "").trim();
  }

  const birthday = String(p.birthday ?? p.date_of_birth ?? "");
  const blood = String(p.blood ?? p.blood_group ?? "");
  const court = String(p.court ?? "");
  const photo = String(p.photo ?? p.photo_key ?? "");

  if (cols.has("birthday")) values.birthday = birthday;
  if (cols.has("date_of_birth")) values.date_of_birth = birthday;

  if (cols.has("blood")) values.blood = blood;
  if (cols.has("blood_group")) values.blood_group = blood;

  if (cols.has("court")) values.court = court;

  if (cols.has("photo")) values.photo = photo;
  if (cols.has("photo_key")) values.photo_key = photo;

  if (cols.has("grade")) {
    const grade = String(p.grade || "").trim();
    values.grade = grade || null;
  }

  if (cols.has("rank")) {
    values.rank = Number(p.rank) || 0;
  }

  if (cols.has("notes")) {
    values.notes = String(p.notes || "");
  }

  if (isNew && cols.has("edit_code")) {
    values.edit_code = Array.from(
      crypto.getRandomValues(new Uint8Array(6)),
      (v) => (v % 36).toString(36)
    ).join("").toUpperCase();
  }

  return values;
}

export async function onRequest({ request, env, params }) {
  try {
    if (!env.DB) {
      return json({
        error: "D1 database binding DB is missing."
      }, 503);
    }

    const route = "/" + (params.path || []).join("/");
    const method = request.method;

    if (route === "/data" && method === "GET") {
      const [players, grades] = await Promise.all([
        env.DB.prepare(
          "SELECT * FROM players ORDER BY name ASC"
        ).all(),
        env.DB.prepare(
          "SELECT * FROM grades ORDER BY sort ASC"
        ).all()
      ]);

      return json({
        players: players.results.map(playerOutput),
        grades: grades.results
      });
    }

    if (route === "/login" && method === "POST") {
      const { password } = await request.json();

      if (!env.ADMIN_PASSWORD) {
        return json({
          error: "ADMIN_PASSWORD secret not configured"
        }, 503);
      }

      if (password !== env.ADMIN_PASSWORD) {
        return json({ error: "Wrong password" }, 401);
      }

      const expiry = String(Date.now() + 8 * 60 * 60 * 1000);

      return json({
        token: expiry + "." +
          await signature(env.ADMIN_PASSWORD, expiry)
      });
    }

    if (route === "/self" && method === "POST") {
      const x = await request.json();
      const cols = await columns(env, "players");

      if (!cols.has("edit_code")) {
        return json({
          error: "Personal code feature requires database setup"
        }, 503);
      }

      const row = await env.DB.prepare(
        "SELECT * FROM players WHERE id=?"
      ).bind(x.id).first();

      if (
        !row ||
        !row.edit_code ||
        row.edit_code !== String(x.code || "")
          .trim().toUpperCase()
      ) {
        return json({ error: "Invalid personal code" }, 403);
      }

      return json({ player: playerOutput(row) });
    }

    if (route === "/self/save" && method === "POST") {
      const x = await request.json();
      const cols = await columns(env, "players");

      if (!cols.has("edit_code")) {
        return json({
          error: "Personal code feature requires database setup"
        }, 503);
      }

      const row = await env.DB.prepare(
        "SELECT * FROM players WHERE id=?"
      ).bind(x.id).first();

      if (
        !row ||
        !row.edit_code ||
        row.edit_code !== String(x.code || "")
          .trim().toUpperCase()
      ) {
        return json({ error: "Invalid personal code" }, 403);
      }

      const values = playerFields({
        name: row.name,
        birthday: x.birthday,
        blood: x.blood,
        court: x.court,
        photo: x.photo,
        grade: row.grade
      }, cols, false);

      delete values.name;
      delete values.grade;
      delete values.rank;
      delete values.notes;

      const keys = Object.keys(values);

      if (cols.has("updated_at")) {
        values.updated_at = new Date().toISOString();
        keys.push("updated_at");
      }

      if (keys.length) {
        await env.DB.prepare(
          `UPDATE players SET ${
            keys.map((k) => `${k}=?`).join(",")
          } WHERE id=?`
        ).bind(...keys.map((k) => values[k]), x.id).run();
      }

      return json({ ok: true });
    }

    if (!(await auth(request, env))) {
      return json({ error: "Admin login required" }, 401);
    }

    if (route === "/players" && method === "POST") {
      const p = await request.json();

      if (!p.name?.trim()) {
        return json({ error: "Player name required" }, 400);
      }

      const cols = await columns(env, "players");
      const isNew = p.id === undefined ||
        p.id === null || p.id === "";

      const values = playerFields(p, cols, isNew);
      const keys = Object.keys(values);

      if (!isNew) {
        if (cols.has("updated_at")) {
          values.updated_at = new Date().toISOString();
          keys.push("updated_at");
        }

        const result = await env.DB.prepare(
          `UPDATE players SET ${
            keys.map((k) => `${k}=?`).join(",")
          } WHERE id=?`
        ).bind(...keys.map((k) => values[k]), p.id).run();

        if (!result.meta?.changes) {
          return json({ error: "Player not found" }, 404);
        }

        return json({ ok: true, id: p.id });
      }

      const result = await env.DB.prepare(
        `INSERT INTO players (${
          keys.join(",")
        }) VALUES (${
          keys.map(() => "?").join(",")
        })`
      ).bind(...keys.map((k) => values[k])).run();

      return json({
        ok: true,
        id: result.meta.last_row_id
      });
    }

    if (route === "/players" && method === "DELETE") {
      const { id } = await request.json();

      if (id === undefined || id === null || id === "") {
        return json({ error: "Player ID required" }, 400);
      }

      await env.DB.prepare(
        "DELETE FROM players WHERE id=?"
      ).bind(id).run();

      return json({ ok: true });
    }

    if (route === "/grades" && method === "POST") {
      const { grades } = await request.json();

      if (!Array.isArray(grades) || grades.length > 100) {
        return json({ error: "Invalid grades" }, 400);
      }

      const names = grades.map((g) =>
        String(g.name || "").trim()
      );

      if (
        names.some((name) => !name) ||
        new Set(names).size !== names.length
      ) {
        return json({
          error: "Grade names must be unique and non-empty"
        }, 400);
      }

      const existing = await env.DB.prepare(
        "SELECT id,name FROM grades"
      ).all();

      const byId = new Map(
        existing.results.map((g) => [String(g.id), g])
      );

      const byName = new Map(
        existing.results.map((g) => [g.name, g])
      );

      const batch = [];

      for (let i = 0; i < grades.length; i++) {
        const g = grades[i];
        const name = names[i];

        const old = (
          g.id !== undefined && g.id !== null
            ? byId.get(String(g.id))
            : null
        ) || byName.get(name);

        if (old) {
          batch.push(
            env.DB.prepare(
              "UPDATE grades SET name=?,sort=? WHERE id=?"
            ).bind(name, i + 1, old.id)
          );
        } else {
          batch.push(
            env.DB.prepare(
              "INSERT INTO grades(name,sort) VALUES(?,?)"
            ).bind(name, i + 1)
          );
        }
      }

      if (batch.length) {
        await env.DB.batch(batch);
      }

      return json({ ok: true });
    }

    if (route === "/grades" && method === "DELETE") {
      const { id } = await request.json();

      if (id === undefined || id === null || id === "") {
        return json({ error: "Grade ID required" }, 400);
      }

      await env.DB.prepare(
        "DELETE FROM grades WHERE id=?"
      ).bind(id).run();

      return json({ ok: true });
    }

    return json({ error: "Not found" }, 404);

  } catch (e) {
    return json({
      error: e.message || "Unexpected error"
    }, 500);
  }
}
