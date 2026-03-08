export class LiveSocket {
    constructor(onMessage, onStatusChange) {
        this.onMessage = onMessage;
        this.onStatusChange = onStatusChange;
        this.ws = null;
        this._reconnectDelay = 1000;
        this._maxDelay = 30000;
        this._timer = null;
    }

    connect() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const url = `${proto}//${location.host}/ws/live`;

        this.ws = new WebSocket(url);

        this.ws.onopen = () => {
            this._reconnectDelay = 1000;
            this.onStatusChange(true);
        };

        this.ws.onmessage = (e) => {
            try {
                const msg = JSON.parse(e.data);
                if (msg.type === 'ping') return; // heartbeat
                this.onMessage(msg);
            } catch (err) {
                console.error('WS parse error:', err);
            }
        };

        this.ws.onclose = () => {
            this.onStatusChange(false);
            this._scheduleReconnect();
        };

        this.ws.onerror = () => {
            this.ws.close();
        };
    }

    _scheduleReconnect() {
        clearTimeout(this._timer);
        this._timer = setTimeout(() => {
            this._reconnectDelay = Math.min(this._reconnectDelay * 1.5, this._maxDelay);
            this.connect();
        }, this._reconnectDelay);
    }

    disconnect() {
        clearTimeout(this._timer);
        if (this.ws) {
            this.ws.onclose = null;
            this.ws.close();
        }
    }
}
