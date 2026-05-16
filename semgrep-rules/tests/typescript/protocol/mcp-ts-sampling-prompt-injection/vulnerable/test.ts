/**
 * Vulnerable TypeScript MCP sampling prompt injection examples — for Semgrep rule testing ONLY.
 * DO NOT deploy this code. It intentionally contains security vulnerabilities.
 */

declare const CreateMessageResultSchema: unknown;

interface McpServer {
    request(params: unknown, schema: unknown): Promise<unknown>;
}

// ruleid: mcp-ts-sampling-template-literal-injection
async function handleFetchTool(server: McpServer, args: { url: string }) {
    const result = await server.request(
        {
            method: "sampling/createMessage",
            params: {
                messages: [{
                    role: "user",
                    content: { type: "text", text: `Fetch and analyze: ${args.url}` }
                }],
                maxTokens: 100
            }
        },
        CreateMessageResultSchema
    );
    return result;
}

// ruleid: mcp-ts-sampling-template-literal-injection
async function handleSummarizeTool(server: McpServer, args: { content: string }) {
    return await server.request(
        {
            method: "sampling/createMessage",
            params: {
                messages: [{ role: "user", content: { type: "text", text: `Summarize: ${args.content}` } }],
                maxTokens: 200
            }
        },
        CreateMessageResultSchema
    );
}

// ruleid: mcp-ts-sampling-createMessage-variable
async function handleVariableText(server: McpServer, args: { prompt: string }) {
    const userText = args.prompt;
    return await server.request(
        {
            method: "sampling/createMessage",
            params: {
                messages: [{ role: "user", content: { type: "text", text: userText } }],
                maxTokens: 150
            }
        },
        CreateMessageResultSchema
    );
}
