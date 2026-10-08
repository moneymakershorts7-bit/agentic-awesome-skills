# Multi-Framework Icon Synchronization Recipes

The `sync_icon` tool and `better-icons get` command allow automated generation of type-safe icon components in any frontend codebase.

---

## 1. React / Next.js / TypeScript (`icons.tsx`)

```tsx
// src/components/icons.tsx
import React from 'react';

export function HomeIcon({ size = 24, color = "currentColor", ...props }: React.SVGProps<SVGSVGElement> & { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
      <polyline points="9 22 9 12 15 12 15 22" />
    </svg>
  );
}
```

---

## 2. Vue 3 SFC (`Icon.vue`)

```vue
<template>
  <svg :width="size" :height="size" viewBox="0 0 24 24" :fill="fill" :stroke="stroke" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <slot />
  </svg>
</template>

<script setup lang="ts">
withDefaults(defineProps<{
  size?: number | string
  stroke?: string
  fill?: string
}>(), {
  size: 24,
  stroke: 'currentColor',
  fill: 'none'
})
</script>
```

---

## 3. Svelte 5 Component (`Icon.svelte`)

```svelte
<script lang="ts">
  let { size = 24, color = 'currentColor', children } = $props();
</script>

<svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  {@render children?.()}
</svg>
```
