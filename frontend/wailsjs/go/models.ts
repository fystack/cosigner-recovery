export namespace app {
	
	export class SweepWalletView {
	    walletId: string;
	    name: string;
	    address: string;
	
	    static createFrom(source: any = {}) {
	        return new SweepWalletView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.walletId = source["walletId"];
	        this.name = source["name"];
	        this.address = source["address"];
	    }
	}
	export class SweepKeysInfo {
	    loaded: boolean;
	    wallets: SweepWalletView[];
	
	    static createFrom(source: any = {}) {
	        return new SweepKeysInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.loaded = source["loaded"];
	        this.wallets = this.convertValues(source["wallets"], SweepWalletView);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SweepTxView {
	    name: string;
	    signer: string;
	    description: string;
	
	    static createFrom(source: any = {}) {
	        return new SweepTxView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.signer = source["signer"];
	        this.description = source["description"];
	    }
	}
	export class SweepPlanView {
	    to: string;
	    txs: SweepTxView[];
	    notes: string[];
	
	    static createFrom(source: any = {}) {
	        return new SweepPlanView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.to = source["to"];
	        this.txs = this.convertValues(source["txs"], SweepTxView);
	        this.notes = source["notes"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SweepResult {
	    log: string[];
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new SweepResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.log = source["log"];
	        this.error = source["error"];
	    }
	}
	

}

export namespace recovery {
	
	export class CombinedKey {
	    protocol: string;
	    privateKeyHex: string;
	    publicKeyHex: string;
	    address: string;
	    addressLabel: string;
	    note: string;
	    verified: boolean;
	    testSigned: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CombinedKey(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.protocol = source["protocol"];
	        this.privateKeyHex = source["privateKeyHex"];
	        this.publicKeyHex = source["publicKeyHex"];
	        this.address = source["address"];
	        this.addressLabel = source["addressLabel"];
	        this.note = source["note"];
	        this.verified = source["verified"];
	        this.testSigned = source["testSigned"];
	    }
	}
	export class HDInfo {
	    loaded: boolean;
	    pending: boolean;
	    fileName: string;
	    masterWalletId: string;
	    childCount: number;
	
	    static createFrom(source: any = {}) {
	        return new HDInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.loaded = source["loaded"];
	        this.pending = source["pending"];
	        this.fileName = source["fileName"];
	        this.masterWalletId = source["masterWalletId"];
	        this.childCount = source["childCount"];
	    }
	}
	export class ShareInfo {
	    id: string;
	    format: string;
	    walletId: string;
	    participantId: string;
	    protocols: string[];
	    unlocked: boolean;
	    needsRsaKey: boolean;
	    needsPassphrase: boolean;
	    cancelled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ShareInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.format = source["format"];
	        this.walletId = source["walletId"];
	        this.participantId = source["participantId"];
	        this.protocols = source["protocols"];
	        this.unlocked = source["unlocked"];
	        this.needsRsaKey = source["needsRsaKey"];
	        this.needsPassphrase = source["needsPassphrase"];
	        this.cancelled = source["cancelled"];
	    }
	}
	export class Status {
	    walletId: string;
	    shares: ShareInfo[];
	    unlockedCounts: Record<string, number>;
	    walletMismatch: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.walletId = source["walletId"];
	        this.shares = this.convertValues(source["shares"], ShareInfo);
	        this.unlockedCounts = source["unlockedCounts"];
	        this.walletMismatch = source["walletMismatch"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

