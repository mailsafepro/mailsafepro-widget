# MailSafePro Premium Widget

Una solución de validación frontend de clase empresarial diseñada para maximizar la conversión y la calidad de los datos. Ingeniería de precisión encapsulada en un componente ligero y sin dependencias.

## 💎 Experiencia de Usuario (UX) Superior

- **Smart Typo Correction**: Detecta y sugiere correcciones automáticas para errores comunes (ej: `gmil.com` → `gmail.com`) con interacción de un solo clic.
- **Feedback Visual Inmersivo**: Iconos flotantes animados, micro-interacciones a 60fps y diseño *Glassmorphism* que se integra elegantemente en cualquier UI moderna.
- **Accesibilidad First**: Soporte nativo ARIA para garantizar una experiencia inclusiva y compatible con lectores de pantalla.

## 🏗️ Arquitectura Técnica

- **Zero-Dependency & Lightweight**: Vanilla JS puro optimizado para tiempos de carga insignificantes.
- **Developer Experience (DX)**: Inicialización automática vía atributos HTML o control total vía API JavaScript. Incluye definiciones TypeScript (`.d.ts`) para un desarrollo tipado y seguro.
- **Resiliencia**: Lógica de *Debounce* adaptativo y manejo de errores de red silenciosos para no bloquear nunca el flujo de registro del usuario.

## 🚀 Instalación Rápida

Agrega el script y configura tu API Key. El widget se inicializa automáticamente.

```html
<script 
    src="https://api.mailsafepro.es/static/mailsafepro-widget.js" 
    data-api-key="TU_API_KEY" 
    data-input-id="email-input"
></script>

<input type="email" id="email-input" placeholder="tu@email.com">
```

**Nota:** También puedes alojar el archivo `mailsafepro-widget.js` en tu propio CDN.

## ⚙️ Configuración Avanzada

Puedes configurar el widget mediante atributos `data-` en la etiqueta `<script>` o instanciándolo manualmente.

### Vía Atributos HTML

| Atributo | Descripción | Default |
|----------|-------------|---------|
| `data-api-key` | Tu clave de API. | - |
| `data-input-id` | ID del input a validar. | - |
| `data-check-smtp` | Activa verificación SMTP profunda. | `false` |
| `data-debounce` | Tiempo de espera (ms) al escribir. | `600` |
| `data-base-url` | URL base de la API (opcional). | `https://api.mailsafepro.es` |

### Vía JavaScript (Para SPAs / React / Vue)

```javascript
// Asegúrate de cargar el script primero
const input = document.getElementById('mi-input');

const widget = new MailSafeProWidget(input, {
    apiKey: 'TU_API_KEY',
    checkSmtp: true,
    showIcons: true,
    messages: {
        valid: '¡Se ve bien!',
        invalid: 'Correo no válido',
        suggestion: '¿Quizás quisiste decir {suggestion}?'
    }
});
```

## 📦 Despliegue a Producción

1.  **Hosting del Script**: Sube el archivo `mailsafepro-widget.js` a tu CDN o servidor estático (ej: AWS S3, Cloudflare R2, o la carpeta `public` de tu servidor web).
2.  **CORS en Backend**: Asegúrate de que tu API permita peticiones desde el dominio donde alojarás el widget.
    -   Si usas FastAPI, asegúrate de tener configurado `CORSMiddleware` con `allow_origins=["*"]` (o tu dominio específico).
3.  **API Key**: Utiliza una API Key válida en producción.
    -   *Nota*: La clave `DEMO_KEY_123` activa el "Modo Demo" para pruebas locales sin backend.

## 🎨 Personalización CSS

El widget inyecta estilos modernos por defecto, pero puedes sobrescribirlos fácilmente.

```css
/* Cambiar color de éxito */
.msp-input-valid {
    border-color: #00C853 !important;
}

/* Personalizar el chip de sugerencia */
.msp-suggestion {
    background-color: #F3E5F5;
    color: #7B1FA2;
}
```

## 📦 TypeScript Support

Incluimos un archivo de definiciones `index.d.ts` para autocompletado en VS Code.

```typescript
import { MailSafeProWidget } from 'mailsafepro-widget';
```

---
© 2025 MailSafePro. All rights reserved.
