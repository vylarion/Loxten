<script>
  import Hero from '$lib/Hero.svelte';
</script>

<main>
  <Hero />
</main>

<style>
  :global(*) {
    box-sizing: border-box;
  }

  :global(body) {
    margin: 0;
    padding: 0;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: #08090a;
    color: #e4e4e7;
    font-size: 14px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }

  main {
    width: 100%;
    display: flex;
    justify-content: center;
    padding: 0;
  }
</style>