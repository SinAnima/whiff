" Commands for the harbour logbook.
if exists('g:loaded_harbour')
  finish
endif
let g:loaded_harbour = 1

source ~/.vim/harbour-tides.vim

" Insert the next high water.
function! harbour#Tide() abort
  return '14:20'
endfunction

command! HarbourTide put =harbour#Tide()
nnoremap <leader>ht :HarbourTide<CR>

augroup harbour
  autocmd!
  autocmd BufRead *.log setlocal nowrap
augroup END
