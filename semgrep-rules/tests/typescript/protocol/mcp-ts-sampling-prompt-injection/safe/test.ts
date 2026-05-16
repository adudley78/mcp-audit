/**
 * Safe TypeScript MCP sampling examples — for Semgrep rule testing ONLY.
 * These patterns should produce zero findings from mcp-ts-sampling-template-literal-injection
 * and mcp-ts-sampling-createMessage-variable.
 */

declare const CreateMessageResultSchema: unknown;

interface McpServer {
    request(params: unknown, schema: unknown): Promise<unknown>;
}

// ok: mcp-ts-sampling-template-literal-injection — literal-only text
// ok: mcp-ts-sampling-createMessage-variable — literal string, not a variable
async function handleToolSafe(server: McpServer) {
    const result = await server.request(
        {
            method: "sampling/createMessage",
            params: {
                messages: [{
                    role: "user",
                    content: { type: "text", text: "What are the top 5 security best practices?" }
                }],
                maxTokens: 100
            }
        },
        CreateMessageResultSchema
    );
    return result;
}

// ok: mcp-ts-sampling-template-literal-injection — fixed system prompt
async function handleAnalyzeSafe(server: McpServer) {
    return await server.request(
        {
            method: "sampling/createMessage",
            params: {
                messages: [{ role: "user", content: { type: "text", text: "List MCP security risks." } }],
                maxTokens: 200
            }
        },
        CreateMessageResultSchema
    );
}
