/// Minimal client for the Canton JSON Ledger API v2 (Canton 3.x), enough for the CLPR relay:
/// DAR upload, party allocation, command submission and active-contract queries.
///
/// Values use the Daml-LF JSON encoding: Int as a decimal string, records as objects, variants as
/// {tag, value}, enums as the constructor name.

export const CLPR_PACKAGE = "#clpr";
export const T = {
    rules: `${CLPR_PACKAGE}:Clpr.Rules:ClprRules`,
    confirmation: `${CLPR_PACKAGE}:Clpr.Rules:Confirmation`,
    channel: `${CLPR_PACKAGE}:Clpr.Channel:Channel`,
    outbound: `${CLPR_PACKAGE}:Clpr.Channel:OutboundMessage`,
    inbound: `${CLPR_PACKAGE}:Clpr.Channel:InboundMessage`,
    sendRequest: `${CLPR_PACKAGE}:Clpr.Channel:SendRequest`
} as const;

export interface Contract<P = Record<string, unknown>> {
    contractId: string;
    templateId: string;
    payload: P;
}

export interface CreatedEventLike {
    contractId: string;
    templateId: string;
    createArgument: Record<string, unknown>;
}

type Command =
    | {CreateCommand: {templateId: string; createArguments: unknown}}
    | {ExerciseCommand: {templateId: string; contractId: string; choice: string; choiceArgument: unknown}};

let commandSeq = 0;

export class CantonLedger {
    constructor(
        readonly baseUrl: string,
        readonly userId = "clpr-relay"
    ) {}

    private async call<R>(path: string, body?: unknown, init?: RequestInit): Promise<R> {
        const res = await fetch(`${this.baseUrl}${path}`, {
            method: body === undefined && !init?.body ? "GET" : "POST",
            headers: {"content-type": "application/json"},
            body: body === undefined ? undefined : JSON.stringify(body),
            ...init
        });
        const text = await res.text();
        if (!res.ok) throw new Error(`Canton ${path} -> ${res.status}: ${text.slice(0, 2000)}`);
        return (text ? JSON.parse(text) : undefined) as R;
    }

    async version(): Promise<string> {
        return (await this.call<{version: string}>("/v2/version")).version;
    }

    async uploadDar(dar: Uint8Array): Promise<void> {
        await this.call("/v2/dars?vetAllPackages=true", undefined, {
            method: "POST",
            headers: {"content-type": "application/octet-stream"},
            body: Buffer.from(dar)
        });
    }

    async allocateParty(hint: string): Promise<string> {
        const r = await this.call<{partyDetails: {party: string}}>("/v2/parties", {
            partyIdHint: hint,
            identityProviderId: ""
        });
        return r.partyDetails.party;
    }

    async ledgerEnd(): Promise<number> {
        return (await this.call<{offset: number}>("/v2/state/ledger-end")).offset;
    }

    /// Submit commands and return the created events of the resulting transaction.
    async submit(actAs: string[], readAs: string[], commands: Command[]): Promise<CreatedEventLike[]> {
        const r = await this.call<{transaction: {events: Array<Record<string, CreatedEventLike>>}}>(
            "/v2/commands/submit-and-wait-for-transaction",
            {
                commands: {
                    commands,
                    commandId: `clpr-${Date.now()}-${++commandSeq}`,
                    userId: this.userId,
                    actAs,
                    readAs
                }
            }
        );
        return r.transaction.events.filter((e) => "CreatedEvent" in e).map((e) => e.CreatedEvent);
    }

    async create(actAs: string, templateId: string, args: unknown): Promise<string> {
        const evs = await this.submit([actAs], [], [{CreateCommand: {templateId, createArguments: args}}]);
        return evs[0].contractId;
    }

    async exercise(
        actAs: string,
        readAs: string[],
        templateId: string,
        contractId: string,
        choice: string,
        choiceArgument: unknown
    ): Promise<CreatedEventLike[]> {
        return this.submit([actAs], readAs, [{ExerciseCommand: {templateId, contractId, choice, choiceArgument}}]);
    }

    /// Active contracts of one template visible to `party`.
    async query<P = Record<string, unknown>>(party: string, templateId: string): Promise<Contract<P>[]> {
        const offset = await this.ledgerEnd();
        const rows = await this.call<Array<{contractEntry: Record<string, {createdEvent: CreatedEventLike}>}>>(
            "/v2/state/active-contracts",
            {
                activeAtOffset: offset,
                eventFormat: {
                    filtersByParty: {
                        [party]: {
                            cumulative: [
                                {identifierFilter: {TemplateFilter: {value: {templateId, includeCreatedEventBlob: false}}}}
                            ]
                        }
                    },
                    verbose: true
                }
            }
        );
        const out: Contract<P>[] = [];
        for (const row of rows) {
            const active = row.contractEntry?.JsActiveContract;
            if (!active) continue;
            const ev = active.createdEvent;
            out.push({contractId: ev.contractId, templateId: ev.templateId, payload: ev.createArgument as P});
        }
        return out;
    }
}
