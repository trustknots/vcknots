import { Hono } from 'hono';
import { VcknotsContext } from '@trustknots/vcknots';
export declare const createVerifierRouter: (context: VcknotsContext, baseUrl: string) => Hono<import("hono/types").BlankEnv, import("hono/types").BlankSchema, "/">;
