/**
 * Codebuff agent type definitions.
 *
 * This file provides the TypeScript types for creating custom Codebuff agents
 * in this repo. Import these types in your `.agents/*.ts` agent files to get
 * full type-checking and editor autocomplete, e.g.:
 *
 *   import type { AgentDefinition } from './types/agent-definition'
 *
 * It is intentionally dependency-free (no zod, no runtime imports) so that
 * agent files type-check standalone.
 *
 * > Update this file if Codebuff's agent schema evolves. A stale type is a bug.
 */

/**
 * The built-in tools an agent may be granted. Grant only what the agent needs.
 */
export type ToolName =
  | 'read_files'
  | 'code_search'
  | 'run_terminal_command'
  | 'spawn_agents'
  | 'str_replace'
  | 'write_file'
  | 'set_output'
  | 'end_turn'

/**
 * A provider-qualified model id, e.g. 'anthropic/claude-sonnet-4' or
 * 'openai/gpt-5'. Kept as a string alias so new models work without edits.
 */
export type ModelName = string

/**
 * How the agent's result is returned to whoever spawned it.
 * - 'last_message'       → the agent's final message (default, simplest)
 * - 'structured_output'  → a JSON object validated against the agent's schema
 * - 'all_messages'       → the full transcript of the agent's run
 */
export type OutputMode = 'last_message' | 'structured_output' | 'all_messages'

/**
 * The shape of the input an agent accepts when spawned.
 */
export interface AgentInputSchema {
  /** Free-text prompt describing the task for the agent. */
  prompt?: {
    type: 'string'
    description?: string
  }
  /** Optional structured parameters the agent accepts alongside the prompt. */
  params?: Record<string, unknown>
}

/**
 * A custom Codebuff agent definition. Export one as the default export of a
 * `.agents/<id>.ts` file.
 */
export interface AgentDefinition {
  /** Unique, kebab-case id used to invoke/spawn the agent (e.g. 'harbor-reviewer'). */
  id: string
  /** Optional publisher handle when publishing the agent. */
  publisher?: string
  /** Human-friendly name shown in the UI. */
  displayName: string
  /** The model this agent runs on (provider-qualified id). */
  model: ModelName
  /** One-liner telling the orchestrator WHEN to spawn this agent. */
  spawnerPrompt?: string
  /** Declares the prompt/params the agent accepts. */
  inputSchema?: AgentInputSchema
  /** How the agent's result is surfaced to the caller. */
  outputMode?: OutputMode
  /** If true, the agent sees the parent conversation history. */
  includeMessageHistory?: boolean
  /** The built-in tools this agent may use. */
  toolNames?: ToolName[]
  /** Ids of other agents this agent is allowed to spawn. */
  spawnableAgents?: string[]
  /** Sets the agent's persona / high-level identity. */
  systemPrompt?: string
  /** Task-specific instructions injected at the start of the agent's run. */
  instructionsPrompt?: string
  /** Instructions injected before each step of a multi-step run. */
  stepPrompt?: string
  /**
   * Optional generator that programmatically drives the agent's steps
   * (advanced). Left loosely-typed here to stay dependency-free.
   */
  handleSteps?: (...args: any[]) => any
}
