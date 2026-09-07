class SecurityWebhookNotifier:
    """Send real-time alerts to Slack or Discord webhooks"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.session = requests.Session()
        
    def send_alert(self, title: str, message: str, severity: str = "HIGH") -> bool:
        """Send formatted alert payload"""
        if not self.webhook_url:
            return False
            
        color = "#FF0000" if severity == "CRITICAL" else "#FFA500"
        
        # Discord / Slack compatible payload structure
        payload = {
            "content": f"🚨 **MHZALY Security Alert: {severity}** 🚨",
            "embeds": [{
                "title": title,
                "description": message,
                "color": 16711680 if severity == "CRITICAL" else 16753920,
                "timestamp": datetime.utcnow().isoformat()
            }]
        }
        
        try:
            response = self.session.post(self.webhook_url, json=payload, timeout=5)
            return response.status_code in [200, 201, 204]
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False
