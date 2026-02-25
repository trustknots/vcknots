import { showRoutes } from 'hono/dev';
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { createAuthzRouter } from './routes/authz.js';
import { createIssueRouter } from './routes/issue.js';
import { createVerifierRouter } from './routes/verify.js';
export const createApp = (context, baseUrl) => {
    const app = new Hono();
    app.route('/', createIssueRouter(context, baseUrl));
    app.route('/', createAuthzRouter(context, baseUrl));
    app.route('/', createVerifierRouter(context, baseUrl));
    app.notFound((c) => c.json({ error: 'Not Found' }, 404));
    app.onError((err, c) => {
        if (err instanceof HTTPException)
            return err.getResponse();
        return c.json({ error: err.message }, 500);
    });
    showRoutes(app, { verbose: true });
    return app;
};
//# sourceMappingURL=app.js.map